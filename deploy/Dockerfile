# The relay, built from this repository.
#   docker build -f deploy/Dockerfile -t messenger-relay .
# docker-compose.yml in this folder builds and runs it for you.

FROM rust:1-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
RUN cargo build --release --locked -p messenger-relay

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data relay \
 && mkdir /data && chown relay /data
COPY --from=build /src/target/release/messenger-relay /usr/local/bin/messenger-relay
USER relay
WORKDIR /data
ENV RELAY_ADDR=0.0.0.0:8080 \
    RELAY_DB=/data/relay.db
EXPOSE 8080
VOLUME /data
CMD ["messenger-relay"]
