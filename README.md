# basic-auth-proxy

Reverse proxy in front of one upstream service. Requests are accepted only
with a valid HTTP Basic or Bearer credential. Credentials are managed from
the admin panel at `/__admin/`, which is protected by a password that is
exchanged for a JWT.

## Layout

- `src/` Rust service (axum, axum-reverse-proxy, axum-vite-spa-bundle, rusqlite)
- `web/` admin SPA (Vue, Nuxt UI, dark theme), built to `web/dist/`

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPSTREAM_URL` | required | Protected service |
| `ADMIN_PASSWORD` | required | Admin panel password |
| `JWT_SECRET` | random per start | Admin JWT signing key |
| `JWT_TTL_HOURS` | `12` | Admin session lifetime |
| `DATABASE_PATH` | `credentials.db` | SQLite file |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Listen address |
| `AUTH_REALM` | `protected` | Realm in `WWW-Authenticate` |
| `SHUTDOWN_GRACE_SECS` | `3` | Time in-flight requests get after SIGINT/SIGTERM |

Every flag has a matching CLI option (`--upstream`, `--database`, ...).

## Build and run

```sh
cd web && npm install && npm run build && cd ..
ADMIN_PASSWORD=... UPSTREAM_URL=http://127.0.0.1:3000 cargo run --release
```

Use `--release`: the admin SPA is embedded only in release builds. Debug
builds proxy `/__admin/` to a Vite dev server instead.

## Docker

```sh
cp .env.example .env   # set ADMIN_PASSWORD and JWT_SECRET
docker compose up --build
```

The sample `docker-compose.yml` runs `traefik/whoami` as the protected
service. Replace the `app` service and `UPSTREAM_URL` with your own.

## Behaviour

- Non-admin requests: `401` with `WWW-Authenticate: Basic` and `Bearer`
  unless a valid credential is sent. Valid requests are forwarded with the
  `Authorization` header removed.
- Basic passwords are stored as SHA-512-crypt hashes (5000 rounds, salted),
  cheap enough for high-volume clients such as Loki. Use long random
  passwords: a fast hash makes offline guessing of weak passwords easier
  than Argon2 would. Bearer tokens are shown once
  at creation; only their SHA-256 digest is stored.
- Credentials are loaded into memory at start and kept in sync with SQLite
  on every create and delete.
- Admin API (under `/__admin/api`): `POST /login`, and JWT-protected
  `GET|POST /credentials`, `DELETE /credentials/{id}`.

## Operations

- `GET /__healthz`: `200 {"status":"ok"}` when SQLite answers, `503` otherwise.
- `GET /__metrics`: Prometheus text format. Counters are in memory and reset on restart.
  - `proxy_auth_failures_total{scheme="none|basic|bearer"}` rejected guard requests
  - `proxy_credential_requests_total{credential="<id>"}` requests forwarded per credential id
  - `admin_login_failures_total` failed admin password attempts

Both paths are answered by the proxy itself and are not forwarded. Neither
requires auth, so restrict them at the network level (for example, scrape
from inside the Docker network only).

## Limits

- No rate limiting on `/__admin/api/login`.
- Restarting without `JWT_SECRET` invalidates admin sessions.
