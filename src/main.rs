mod admin;
mod auth;
mod config;
mod ops;
mod secrets;
mod store;
mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use axum_reverse_proxy::ReverseProxy;
use clap::Parser;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use ipnet::IpNet;
use tokio::signal::unix::SignalKind;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::secrets::{hash_password, random_bytes};
use crate::store::Store;
use crate::upstream::{HostTable, RequestHost, Routing, Target};

/// Shared state handed to every handler and middleware.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub admin_hash: Arc<str>,
    pub jwt_secret: Arc<[u8]>,
    pub jwt_ttl_secs: u64,
    pub realm: Arc<str>,
    pub metrics: metrics_exporter_prometheus::PrometheusHandle,
}

fn proxy_router(target: &Target) -> Router {
    if !target.h2c {
        return ReverseProxy::new("", &target.url).into();
    }
    // HTTP/2 prior-knowledge (h2c) client for upstreams marked `!h2c`.
    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(HttpConnector::new());
    ReverseProxy::new_with_client("", &target.url, client).into()
}

/// Forwards to the upstream whose hostname matches the request host.
async fn dispatch_by_host(
    State(table): State<Arc<HostTable>>,
    RequestHost(host): RequestHost,
    req: Request,
) -> Response {
    match table.routes.get(&host) {
        Some(router) => router
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|never| match never {}),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn build_app(state: AppState, routing: &Routing, trusted_proxies: Vec<IpNet>) -> Router {
    // Everything except /__admin/ goes through the credential guard and then
    // to the protected service(s).
    let proxy: Router = match routing {
        Routing::Single(target) => proxy_router(target),
        Routing::ByHost(routes) => {
            let table = HostTable {
                routes: routes
                    .iter()
                    .map(|r| (r.host.clone(), proxy_router(&r.target)))
                    .collect(),
                trusted_proxies,
            };
            Router::new()
                .fallback(dispatch_by_host)
                .with_state(Arc::new(table))
        }
    };
    let guarded = proxy.layer(from_fn_with_state(state.clone(), auth::guard));

    // `nest` matches /__admin and /__admin/<rest> but not the bare trailing
    // slash, so that exact path is routed to the admin app explicitly.
    let admin = admin::router(state.clone());
    let admin_exact = admin.clone().with_state(state.clone());

    Router::new()
        .route("/__metrics", get(ops::metrics))
        .route("/__healthz", get(ops::healthz))
        .route_service(
            "/__admin/",
            admin_exact.into_service::<axum::body::Body>(),
        )
        .nest("/__admin", admin)
        .fallback_service(guarded)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Two rustls providers are linked (ring and aws-lc-rs); pick one before
    // the reverse proxy builds its TLS client.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = Config::parse();

    let store = Store::open(&cfg.database)?;
    let state = AppState {
        store: Arc::new(store),
        admin_hash: hash_password(&cfg.admin_password)?.into(),
        jwt_secret: match cfg.jwt_secret {
            Some(secret) => secret.into_bytes().into(),
            None => {
                tracing::warn!("JWT_SECRET not set: using a random key, admin sessions end on restart");
                random_bytes().to_vec().into()
            }
        },
        jwt_ttl_secs: cfg.jwt_ttl_hours * 3600,
        realm: cfg.realm.into(),
        metrics: ops::install_recorder()?,
    };

    let routing = Routing::try_from(cfg.upstream.clone()).map_err(anyhow::Error::msg)?;
    match &routing {
        Routing::Single(target) => {
            tracing::info!(upstream = %target.url, h2c = target.h2c, "single upstream, all hosts forwarded");
        }
        Routing::ByHost(routes) => {
            for r in routes {
                tracing::info!(host = %r.host, upstream = %r.target.url, h2c = r.target.h2c, "host routed");
            }
        }
    }

    if !cfg.trusted_proxies.is_empty() {
        tracing::info!(trusted = ?cfg.trusted_proxies, "X-Forwarded-Host accepted from these peers");
    }
    let app = build_app(state, &routing, cfg.trusted_proxies.clone());
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, "proxy listening");

    let grace = Duration::from_secs(cfg.shutdown_grace_secs);
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        shutdown_signal().await;
        tracing::info!("shutdown signal received, draining in-flight requests");
    });

    // Graceful drain, but never longer than the grace period once a signal arrives.
    tokio::select! {
        result = server => result?,
        () = force_exit_after_grace(grace) => {
            tracing::warn!("grace period elapsed, exiting with requests still in flight");
        }
    }
    tracing::info!("stopped");
    Ok(())
}

/// Resolves on SIGINT (Ctrl+C) or SIGTERM (docker stop, systemd).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    let terminate = async {
        tokio::signal::unix::signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

async fn force_exit_after_grace(grace: Duration) {
    shutdown_signal().await;
    tokio::time::sleep(grace).await;
}
