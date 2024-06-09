# BUILD
# ---------------------------------------------------------------------
FROM rust:bookworm as builder
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"

ARG GIT_URI='https://github.com/stacks-network/stacks-core.git'
ARG GIT_COMMIT
RUN test -n "$GIT_COMMIT" || (echo "GIT_COMMIT not set" && false)

RUN echo "Building stacks from commit: https://github.com/stacks-network/stacks-core/commit/$GIT_COMMIT"

RUN apt-get update && apt-get install -y libclang-dev
RUN rustup toolchain install stable
RUN rustup component add rustfmt --toolchain stable

WORKDIR /stacks
RUN git init && git remote add origin $GIT_URI && git -c protocol.version=2 fetch --depth=1 origin "$GIT_COMMIT" && git reset --hard FETCH_HEAD
RUN cargo build --package stacks-node --bin stacks-node


# RUNNER
# ---------------------------------------------------------------------
FROM debian:bookworm

# copy over stacks-node binary
COPY --from=builder /stacks/target/debug/stacks-node /usr/local/bin/

# install & setup utils
RUN apt-get update && apt-get install -y curl gettext-base jq sudo
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# copy over stacks node config
COPY . .

RUN chmod +rwx ./entrypoint.sh

EXPOSE 20444
EXPOSE 20443

CMD ["./entrypoint.sh"]