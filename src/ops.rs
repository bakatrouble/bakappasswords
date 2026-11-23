//! Operational endpoints: Prometheus scrape and health probe.
//!
//! Counters are in-memory only and reset on restart.

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use metrics::{describe_counter, Unit};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::AppState;

pub const AUTH_FAILURES: &str = "proxy_auth_failures_total";
pub const CREDENTIAL_REQUESTS: &str = "proxy_credential_requests_total";
pub const ADMIN_LOGIN_FAILURES: &str = "admin_login_failures_total";

/// Installs the global recorder and returns the handle used to render it.
/// Must run before any metric is recorded.
pub fn install_recorder() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new().install_recorder()?;

    describe_counter!(
        AUTH_FAILURES,
        Unit::Count,
        "Requests rejected by the proxy guard, by scheme (none, basic, bearer)"
    );
    describe_counter!(
        CREDENTIAL_REQUESTS,
        Unit::Count,
        "Requests forwarded to the upstream, per credential id"
    );
    describe_counter!(
        ADMIN_LOGIN_FAILURES,
        Unit::Count,
        "Failed admin panel password attempts"
    );

    Ok(handle)
}

/// GET /__metrics: Prometheus text exposition format.
pub async fn metrics(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render(),
    )
        .into_response()
}

/// GET /__healthz: 200 when the credential database answers, 503 otherwise.
pub async fn healthz(State(state): State<AppState>) -> Response {
    match state.store.ping() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "status": "unavailable" })),
            )
                .into_response()
        }
    }
}
