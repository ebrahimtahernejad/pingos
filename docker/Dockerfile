# Multi-stage build: produces a slim image with the `pingos` binary.

FROM rust:1.95-slim AS builder

WORKDIR /src

# Cache deps separately so source edits don't blow the layer cache.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src tests \
 && printf 'fn main() {}\n' > src/main.rs \
 && printf '\n' > src/lib.rs \
 && cargo fetch \
 && cargo build --release --bin pingos --quiet || true

# Real build.
COPY src ./src
COPY tests ./tests
# Force rebuild of the binary (since src/main.rs changed).
RUN touch src/main.rs src/lib.rs && cargo build --release --bin pingos

# ---- Runtime image ----
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends netcat-openbsd ca-certificates iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/pingos /usr/local/bin/pingos

ENTRYPOINT ["/usr/local/bin/pingos"]
