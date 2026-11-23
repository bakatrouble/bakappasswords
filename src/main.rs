mod admin;
mod auth;
mod config;
mod ops;
mod secrets;
mod store;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum_reverse_proxy::ReverseProxy;
use clap::Parser;
use tokio::signal::unix::SignalKind;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::secrets::{hash_password, random_bytes};
use crate::store::Store;

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

fn build_app(state: AppState, upstream: &str) -> Router {
    // Everything except /__admin/ goes through the credential guard and then
    // to the protected service.
    let proxy: Router = ReverseProxy::new("", upstream).into();
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

    let app = build_app(state, &cfg.upstream);
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, "proxy listening");

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
