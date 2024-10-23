FROM sbtc-build:latest AS build
FROM debian:bookworm-slim AS runtime
COPY --from=build /code/sbtc/target/debug/sbtc-signer /usr/local/bin/sbtc-signer
ENTRYPOINT ["/usr/local/bin/sbtc-signer --config /signer-config.toml --migrate-db"]
