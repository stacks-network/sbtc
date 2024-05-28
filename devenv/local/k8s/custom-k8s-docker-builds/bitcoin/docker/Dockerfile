FROM debian:stable-slim as builder
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>

ARG VERSION=25.0


ARG BTC_NETWORK
ARG BTC_TXINDEX
ARG BTC_RPCUSER
ARG BTC_RPCPASSWORD
ARG BTC_PRINTTOCONSOLE
ARG BTC_DISABLEWALLET
ARG BTC_RPCBIND
ARG BTC_RPCALLOWIP
ARG BTC_RPC_PORT
ARG BTC_P2P_PORT

# Set ENVs so they persist after image is built
ENV BTC_NETWORK=$BTC_NETWORK
ENV BTC_TXINDEX=$BTC_TXINDEX
ENV BTC_RPCUSER=$BTC_RPCUSER
ENV BTC_RPCPASSWORD=$BTC_RPCPASSWORD
ENV BTC_PRINTTOCONSOLE=$BTC_PRINTTOCONSOLE
ENV BTC_DISABLEWALLET=$BTC_DISABLEWALLET
ENV BTC_RPCBIND=$BTC_RPCBIND
ENV BTC_RPCALLOWIP=$BTC_RPCALLOWIP
ENV BTC_RPC_PORT=$BTC_RPC_PORT
ENV BTC_P2P_PORT=$BTC_P2P_PORT

RUN apt-get update && apt-get install -y \
    wget \
    file \
  && rm -rf /var/lib/apt/lists/*

RUN file /bin/bash | grep -q x86-64 && echo x86_64-linux-gnu > /tmp/arch || true
RUN file /bin/bash | grep -q aarch64 && echo aarch64-linux-gnu > /tmp/arch || true
RUN file /bin/bash | grep -q EABI5 && echo arm-linux-gnueabihf > /tmp/arch || true

RUN wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-$(cat /tmp/arch).tar.gz 

RUN wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS

RUN cat SHA256SUMS | grep bitcoin-${VERSION}-$(cat /tmp/arch).tar.gz | sha256sum -c && \
    mkdir /bitcoin && \
    tar -xzvf bitcoin-${VERSION}-$(cat /tmp/arch).tar.gz -C /bitcoin --strip-components=1

FROM debian:stable-slim as runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    coreutils \
    nginx \
    sudo \
    curl \
    jq && rm -rf /var/lib/apt/lists/*

COPY --from=builder /bitcoin/bin/* /usr/local/bin/

COPY default.conf /etc/nginx/conf.d/default.conf/

ADD entrypoint.sh /usr/local/bin
RUN chmod a+x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
