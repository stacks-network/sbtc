FROM blockstack/stacks-core:2.5.0.0.3
LABEL org.opencontainers.image.authors="Gowtham Sundar <gowtham@trustmachines.co>"
COPY . .

ARG STACKS_LOG_DEBUG
ARG STACKS_LOG_JSON
ARG LOCAL_PEER_SEED
ARG STACKS_WORKING_DIR
ARG MY_HTTP_AUTH_TOKEN
ARG SIGNER_ENDPOINT
ARG MINER_KEY
ARG BTC_NODE_RPC_HOST
ARG BTC_NODE_RPC_USER
ARG BTC_NODE_RPC_PASSWORD


ENV STACKS_LOG_DEBUG=$STACKS_LOG_DEBUG
ENV STACKS_LOG_JSON=$STACKS_LOG_JSON
ENV LOCAL_PEER_SEED=$LOCAL_PEER_SEED
ENV STACKS_WORKING_DIR=$STACKS_WORKING_DIR
ENV MY_HTTP_AUTH_TOKEN=$MY_HTTP_AUTH_TOKEN
ENV SIGNER_ENDPOINT=$SIGNER_ENDPOINT
ENV MINER_KEY=$MINER_KEY
ENV BTC_NODE_RPC_HOST=$BTC_NODE_RPC_HOST
ENV BTC_NODE_RPC_USER=$BTC_NODE_RPC_USER
ENV BTC_NODE_RPC_PASSWORD=$BTC_NODE_RPC_PASSWORD


# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo jq curl

# RUN adduser --disabled-password --gecos '' docker
# RUN adduser docker sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY config.toml .
# --------------------------------------------
# The container creates this the config.toml internally
RUN chmod +rwx ./entrypoint.sh
# RUN sudo ./entrypoint.sh 
# --------------------------------------------


# COPY node-config.toml /config.toml
EXPOSE 20444
EXPOSE 20443
# CMD ["stacks-node", "start", "--config", "/config.toml"]
CMD ["./entrypoint.sh"]