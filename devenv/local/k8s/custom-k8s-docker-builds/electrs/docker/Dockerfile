# --------------------------------------------------------
FROM debian:bookworm-slim as builder
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>
RUN apt-get update -qqy
RUN apt-get install -qqy librocksdb-dev curl git
# --------------------------------------------------------
### Electrum Rust Server ###
FROM builder as electrs-build
RUN apt-get install -qqy cargo clang cmake
ARG GIT_URI='https://github.com/mempool/electrs.git'
ARG GIT_BRANCH='mempool'
# Install electrs
WORKDIR /build/electrs
RUN git clone ${GIT_URI} -b ${GIT_BRANCH} .
RUN cargo install --locked --path .
# --------------------------------------------------------
FROM builder as result
# Copy the binaries
COPY --from=electrs-build /root/.cargo/bin/electrs /usr/bin/electrs

ARG RUST_BACKTRACE
ARG BITCOIN_RPC_HOST
ARG BITCOIN_RPC_PORT

ENV RUST_BACKTRACE=$RUST_BACKTRACE
ENV BITCOIN_RPC_HOST=$BITCOIN_RPC_HOST
ENV BITCOIN_RPC_PORT=$BITCOIN_RPC_PORT


COPY entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh
RUN apt-get update -qqy
RUN apt-get install -qqy jq 
EXPOSE 3002
EXPOSE 60401
WORKDIR /
ENTRYPOINT ["./entrypoint.sh"]