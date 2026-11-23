use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, HeaderMapExt};
use axum_vite_spa_bundle::{SpaConfig, spa_router};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp};
use rusqlite::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::secrets::verify_password;
use crate::store::Credential;
use crate::AppState;

/// Built by `vite build` in web/, embedded into the binary in release.
#[derive(Clone, Copy, rust_embed::Embed)]
#[folder = "web/dist/"]
struct AdminAssets;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum NewCredential {
    Basic {
        label: String,
        username: String,
        password: String,
    },
    Bearer {
        label: String,
    },
}

#[derive(Serialize)]
struct Created {
    #[serde(flatten)]
    credential: Credential,
    /// Present only for bearer credentials, and only in this response.
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Mounted under /__admin: API routes first, then the SPA bundle as fallback.
pub fn router(state: AppState) -> Router<AppState> {
    let api = Router::new()
        .route("/login", post(login))
        .merge(
            Router::new()
                .route("/credentials", get(list).post(create))
                .route("/credentials/{id}", delete(remove))
                .route_layer(middleware::from_fn_with_state(state, require_admin)),
        );

    let spa = spa_router(SpaConfig::new(
        AdminAssets,
        "WEB_DEV_URL",
        "http://127.0.0.1:5173",
        ["/api/"],
    ));

    Router::new().nest("/api", api).merge(spa)
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let hash = state.admin_hash.clone();
    let password = req.password;
    let ok = tokio::task::spawn_blocking(move || verify_password(&hash, &password))
        .await
        .unwrap_or(false);
    if !ok {
        metrics::counter!(crate::ops::ADMIN_LOGIN_FAILURES).increment(1);
        return Err((StatusCode::UNAUTHORIZED, "invalid password".into()));
    }

    let iat = get_current_timestamp();
    let exp = iat + state.jwt_ttl_secs;
    let claims = Claims {
        sub: "admin".into(),
        iat,
        exp,
    };
    let key = EncodingKey::from_secret(&state.jwt_secret).map_err(internal)?;
    let token = encode(&Header::new(Algorithm::HS256), &claims, &key).map_err(internal)?;

    Ok(Json(LoginResponse {
        token,
        expires_at: exp,
    }))
}

/// Rejects requests without a valid admin JWT.
async fn require_admin(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(Authorization(bearer)) = req.headers().typed_get::<Authorization<Bearer>>() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(key) = DecodingKey::from_secret(&state.jwt_secret) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if decode::<Claims>(bearer.token(), &key, &Validation::new(Algorithm::HS256)).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

async fn list(State(state): State<AppState>) -> Json<Vec<Credential>> {
    Json(state.store.list())
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<NewCredential>,
) -> ApiResult<(StatusCode, Json<Created>)> {
    let created = match body {
        NewCredential::Basic {
            label,
            username,
            password,
        } => {
            if username.is_empty() || password.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "username and password are required".into(),
                ));
            }
            let credential = state
                .store
                .create_basic(&label, &username, &password)
                .map_err(db_error)?;
            Created {
                credential,
                token: None,
            }
        }
        NewCredential::Bearer { label } => {
            let (credential, token) = state.store.create_bearer(&label).map_err(db_error)?;
            Created {
                credential,
                token: Some(token),
            }
        }
    };
    Ok((StatusCode::CREATED, Json(created)))
}

async fn remove(State(state): State<AppState>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    let removed = state.store.delete(id).map_err(db_error)?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "no such credential".into()))
    }
}

fn internal(err: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

/// Maps a database error to HTTP: unique-username clashes become 409.
fn db_error(err: anyhow::Error) -> (StatusCode, String) {
    if let Some(rusqlite::Error::SqliteFailure(e, _)) = err.downcast_ref::<rusqlite::Error>()
        && e.code == ErrorCode::ConstraintViolation
    {
        return (StatusCode::CONFLICT, "username already exists".into());
    }
    tracing::error!(error = %err, "credential store failure");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}
