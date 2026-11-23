# syntax=docker/dockerfile:1
# Three stages: admin SPA build, Rust release build (musl), minimal Alpine runtime.

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# rust-embed reads web/dist at compile time, so the SPA build must come first.
COPY --from=web /src/web/dist ./web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/basic-auth-proxy /usr/local/bin/basic-auth-proxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
 && mkdir /data
WORKDIR /app
COPY --from=build /usr/local/bin/basic-auth-proxy /app/basic-auth-proxy

LABEL org.opencontainers.image.source="https://github.com/bakatrouble/bakappasswords"

ENV LISTEN_ADDR=0.0.0.0:8080 \
    DATABASE_PATH=/data/credentials.db
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/app/basic-auth-proxy"]
