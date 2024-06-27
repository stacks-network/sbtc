# BUILDER
# -------------------------------------------------------------------------------
FROM rust:bookworm as builder
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>

ARG GIT_URI='https://github.com/stacks-network/stacks-core.git'
ARG GIT_COMMIT='3d96d53b35409859ca2baa2f0b6ddaa1fbd80265'

RUN echo "Building stacks from commit: https://github.com/stacks-network/stacks-core/commit/$GIT_COMMIT"

RUN apt-get update && apt-get install -y libclang-dev
RUN rustup toolchain install stable
RUN rustup component add rustfmt --toolchain stable

WORKDIR /stacks
RUN git init && git remote add origin $GIT_URI && git -c protocol.version=2 fetch --depth=1 origin "$GIT_COMMIT" && git reset --hard FETCH_HEAD
RUN cargo build --package stacks-signer --bin stacks-signer

# RUNNER
# -------------------------------------------------------------------------------
FROM debian:bookworm

# copy over stacks-signer binary
COPY --from=builder /stacks/target/debug/stacks-signer /usr/local/bin/


ARG SIGNER_ENDPOINT
ARG MY_HTTP_AUTH_TOKEN
ARG STACKS_PRIVATE_KEY
ARG STACKS_NODE_RPC_HOST
ARG STACKS_NODE_RPC_PORT
ARG RUST_BACKTRACE
ARG SIGNER_DB_PATH
ARG GIT_URI
ARG GIT_COMMIT


ENV SIGNER_ENDPOINT=$SIGNER_ENDPOINT
ENV MY_HTTP_AUTH_TOKEN=$MY_HTTP_AUTH_TOKEN
ENV STACKS_PRIVATE_KEY=$STACKS_PRIVATE_KEY
ENV STACKS_NODE_RPC_HOST=$STACKS_NODE_RPC_HOST
ENV STACKS_NODE_RPC_PORT=$STACKS_NODE_RPC_PORT
ENV RUST_BACKTRACE=$RUST_BACKTRACE
ENV SIGNER_DB_PATH=$SIGNER_DB_PATH
ENV GIT_URI=$GIT_URI
ENV GIT_COMMIT=$GIT_COMMIT



# install & setup utils
RUN apt-get update && apt-get install -y curl gettext-base jq sudo
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers


# -------------ENTRYPOINT---------------------
COPY entrypoint.sh .
RUN chmod +rwx ./entrypoint.sh

EXPOSE 30000
CMD ["./entrypoint.sh"]