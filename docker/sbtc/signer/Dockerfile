FROM sbtc-build:latest AS build
FROM debian:bookworm-slim AS runtime
COPY --from=build /code/sbtc/target/debug/signer /usr/local/bin/signer
ENTRYPOINT ["/usr/local/bin/signer --config /signer-config.toml --migrate-db"]
