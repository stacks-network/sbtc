FROM sbtc-build:latest AS build

# Service.
# --------
FROM debian:bookworm-slim AS runtime
COPY --from=build /code/sbtc/target/debug/blocklist-client /usr/local/bin/blocklist-client
# TODO(TBD): Fix the blocklist client so it has a configurable config location.

RUN apt-get update && apt-get install -y ca-certificates --no-install-recommends && \
        apt-get clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/blocklist-client"]
