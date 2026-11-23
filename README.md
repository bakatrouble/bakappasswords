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
| `UPSTREAM_URL` | required | Protected service: one URL, or one `external.domain=upstream-url` entry (see Behaviour). Use `--upstream` repeatedly for several entries |
| `ADMIN_PASSWORD` | required | Admin panel password |
| `JWT_SECRET` | random per start | Admin JWT signing key |
| `JWT_TTL_HOURS` | `12` | Admin session lifetime |
| `TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDRs (e.g. the Caddy host). Only these peers may set `X-Forwarded-Host` |
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

- Upstreams: with a single plain URL, every request goes to it. To serve
  several upstreams, give every entry as `external.domain=upstream-url`, e.g.
  `--upstream app.example.com=http://app:80 --upstream api.example.com=http://api:8000`.
  The `UPSTREAM_URL` environment variable carries a single entry only.
  Requests are forwarded to the upstream whose hostname matches the `Host`
  header (port ignored, case-insensitive); unknown hosts get `404` after the
  credential check. Hostnames must be unique. Mixing plain URLs with
  `host=url` entries is a startup error.
- Host source: when the TCP peer is in `TRUSTED_PROXIES`, the last
  `X-Forwarded-Host` value is used (this is what Caddy sets). Otherwise the
  `Host` header is used, and `X-Forwarded-Host` from any peer is ignored.
  Caddy must be reachable from the proxy's peer address, so list the address
  Caddy connects from (for example its Docker network IP or subnet).
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

## Protocols

- Clients: HTTP/1.1 and cleartext HTTP/2 (h2c) with prior knowledge, on the
  same listen port. The `Upgrade: h2c` handshake from HTTP/1.1 is not used;
  such clients stay on HTTP/1.1.
- Upstreams: HTTP/1.1 by default. An upstream URL with the `!h2c` suffix is
  reached with HTTP/2 prior knowledge (cleartext h2c), e.g.
  `--upstream tempo.example.com=http://tempo:4317!h2c`. The suffix works on
  both plain and `host=url` entries and needs an `http://` URL. Only
  upstreams that serve h2c should be marked; an unmarked HTTP/2-only upstream
  returns `502`.

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
