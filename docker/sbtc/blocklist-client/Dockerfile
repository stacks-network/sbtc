FROM sbtc-build:latest AS build

# Service.
# --------
FROM debian:bookworm-slim AS runtime
COPY --from=build /code/sbtc/target/debug/blocklist-client /usr/local/bin/blocklist-client
# TODO(TBD): Fix the blocklist client so it has a configurable config location.
ENTRYPOINT ["/usr/local/bin/blocklist-client"]
