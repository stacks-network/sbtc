FROM debian:bookworm

COPY --from=dobtc/bitcoin:25.1 /opt/bitcoin-*/bin /usr/local/bin

RUN apt-get update && apt-get install --no-install-recommends -y curl jq zstd && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ADD data.tar.gz /data/bitcoin-data

CMD ["/bin/bash"]
