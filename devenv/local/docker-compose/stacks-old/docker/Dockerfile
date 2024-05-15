FROM rust:alpine as build

ARG STACKS_NODE_VERSION='2.4.0.0.0'
ARG GIT_URI='https://github.com/stacks-network/stacks-blockchain.git'
ARG GIT_BRANCH='2.4.0.0.0'

# ENV STACKS_NETWORK=mainnet
ENV STACKS_NETWORK=mocknet

WORKDIR /src

RUN apk add --no-cache musl-dev git

RUN git clone ${GIT_URI} -b ${GIT_BRANCH} .

RUN mkdir /out

RUN cd testnet/stacks-node && cargo build --features monitoring_prom,slog_json --release

RUN cp target/release/stacks-node /out

FROM alpine

COPY --from=build /out/ /bin/

COPY Config.toml /src/stacks-node/Config.toml

COPY entrypoint.sh /bin/entrypoint.sh

RUN chmod a+x /bin/entrypoint.sh

ENTRYPOINT ["/bin/entrypoint.sh"]
