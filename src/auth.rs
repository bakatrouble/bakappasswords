use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::headers::authorization::{Basic, Bearer};
use axum_extra::headers::{Authorization, HeaderMapExt};
use metrics::counter;

use crate::AppState;
use crate::ops::{AUTH_FAILURES, CREDENTIAL_REQUESTS};

/// Accepts a request if it carries a valid Basic or Bearer credential.
/// The Authorization header is removed before forwarding so the upstream
/// never sees the proxy's credentials.
pub async fn guard(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let (scheme, matched) = if let Some(Authorization(basic)) =
        req.headers().typed_get::<Authorization<Basic>>()
    {
        let id = state
            .store
            .verify_basic(basic.username(), basic.password())
            .await;
        ("basic", id)
    } else if let Some(Authorization(bearer)) = req.headers().typed_get::<Authorization<Bearer>>() {
        ("bearer", state.store.verify_bearer(bearer.token()))
    } else {
        ("none", None)
    };

    let Some(credential_id) = matched else {
        counter!(AUTH_FAILURES, "scheme" => scheme).increment(1);
        return unauthorized(&state.realm);
    };

    counter!(CREDENTIAL_REQUESTS, "credential" => credential_id.to_string()).increment(1);
    req.headers_mut().remove(header::AUTHORIZATION);
    next.run(req).await
}

fn unauthorized(realm: &str) -> Response {
    let mut res = StatusCode::UNAUTHORIZED.into_response();
    let headers = res.headers_mut();
    for scheme in ["Basic", "Bearer"] {
        let value = format!("{scheme} realm=\"{realm}\"");
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.append(header::WWW_AUTHENTICATE, value);
        }
    }
    res
}
