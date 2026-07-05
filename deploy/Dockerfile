# Build the rendezvous server + the WASM web viewer. Build context is the
# workspace root (see docker-compose.yml `context: ..`). Only `rmd-rendezvous`
# and its deps are compiled for the server; the native host/viewer crates are not.

# --- Web viewer (WASM) bundle ---------------------------------------------
# Produces the browser viewer's static assets, served by the rendezvous at /app.
FROM rust:1-slim AS webviewer
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
# No protoc: rmd-protocol compiles its schema with the pure-Rust `protox`.
RUN rustup target add wasm32-unknown-unknown \
    && cargo install trunk --locked --version ^0.21
COPY . .
RUN cd apps/web-viewer \
    && trunk build --release --public-url /app/ --dist /build/web-viewer-dist

# --- Rendezvous server -----------------------------------------------------
FROM rust:1-slim AS builder
WORKDIR /build
# No protoc needed (protox). pkg-config + cc (in the rust image) cover the
# bundled SQLite build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p rmd-rendezvous

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/rmd-rendezvous /usr/local/bin/rmd-rendezvous
COPY --from=webviewer /build/web-viewer-dist /srv/web-viewer
ENV RMD_RZ_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:/data/rmd.db?mode=rwc \
    RMD_WEBVIEWER_DIR=/srv/web-viewer
VOLUME ["/data"]
EXPOSE 8080
USER 1000:1000
ENTRYPOINT ["rmd-rendezvous"]
