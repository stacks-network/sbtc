# Needed ENV Variables:

#  BITCOIN_RPC_HOST
#  BITCOIN_RPC_PORT
#  MINER_ADDRESS
#  INIT_BTC_BLOCKS

FROM alpine:latest
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>

RUN apk add --no-cache curl

COPY entrypoint.sh /bin/entrypoint.sh

RUN chmod a+x /bin/entrypoint.sh

ENTRYPOINT ["/bin/entrypoint.sh"]
