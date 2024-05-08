FROM debian:stable-slim as builder
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>

ARG VERSION=25.0

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
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /bitcoin/bin/* /usr/local/bin

COPY default.conf /etc/nginx/conf.d/default.conf
EXPOSE 18443
EXPOSE 18444
EXPOSE 18433
ADD entrypoint.sh /usr/local/bin
RUN chmod a+x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
