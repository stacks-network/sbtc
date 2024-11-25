FROM sbtc-build:latest AS build

FROM debian:bookworm-slim AS runtime
COPY --from=build /code/sbtc/target/debug/signer /usr/local/bin/signer

RUN apt-get update && apt-get install -y ca-certificates --no-install-recommends && \
        apt-get clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/signer --config /signer-config.toml --migrate-db"]
