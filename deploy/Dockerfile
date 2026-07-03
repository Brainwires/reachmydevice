# Build the rendezvous server. Build context is the workspace root (see
# docker-compose.yml `context: ..`). Only `openreach-rendezvous` and its deps
# (openreach-protocol + axum/sqlx/...) are compiled; the native host/viewer
# crates are not built here.
FROM rust:1-slim AS builder
WORKDIR /build
# protoc is needed by openreach-protocol's build script.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p openreach-rendezvous

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/openreach-rendezvous /usr/local/bin/openreach-rendezvous
ENV OPENREACH_RZ_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:/data/openreach.db?mode=rwc
VOLUME ["/data"]
EXPOSE 8080
USER 1000:1000
ENTRYPOINT ["openreach-rendezvous"]
