FROM sbtc-build:latest AS build
RUN cargo build --bin emily-server

# Create Docker image to run the emily server.
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS emily-server
WORKDIR /code
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /code/sbtc/target/debug/emily-server /usr/local/bin/emily-server

# Server configuration.
ENV HOST=0.0.0.0
ENV PORT=3030
# AWS configuration.
ENV AWS_ACCESS_KEY_ID=xxxxxxxxxxxx
ENV AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxx
ENV AWS_REGION=us-west-2
ENV DYNAMODB_ENDPOINT=http://dynamodb:8000

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/emily-server --host $HOST --port $PORT --dynamodb-endpoint $DYNAMODB_ENDPOINT"]
