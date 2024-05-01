FROM blockstack/stacks-core:2.5.0.0.3
MAINTAINER Gowtham Sundar <gowtham@trustmachines.co>
COPY . .
# -----------INSTALL SUDO----------------------
RUN apt-get update && apt-get install -y sudo

# RUN adduser --disabled-password --gecos '' docker
# RUN adduser docker sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# --------------------------------------------
# The container creates this the config.toml internally
RUN chmod +rwx ./entrypoint.sh
RUN sudo ./entrypoint.sh 
# --------------------------------------------


# COPY node-config.toml /config.toml
EXPOSE 20444
EXPOSE 20443
CMD ["stacks-node", "start", "--config", "/config.toml"]


# THESE ARE SOME OF THE NECESSARY ENVS: (https://github.com/hirosystems/stacks-regtest-env/blob/d4cfc79db1913d2ddb0909b56c01488596c06167/docker-compose.yml#L7C17-L7C83)

# - STACKS_BLOCKCHAIN_COMMIT
# - STACKS_API_COMMIT
# - BTC_ADDR
# - MINER_SEED
# - BITCOIN_PEER_PORT
# - BITCOIN_RPC_PORT
# - BITCOIN_RPC_USER
# - BITCOIN_RPC_PASS
# - MINE_INTERVAL
# - MINE_INTERVAL_EPOCH25
# - MINE_INTERVAL_EPOCH3
# - NAKAMOTO_BLOCK_INTERVAL
# - STACKS_20_HEIGHT
# - STACKS_2_05_HEIGHT
# - STACKS_21_HEIGHT
# - STACKS_POX2_HEIGHT
# - STACKS_22_HEIGHT
# - STACKS_23_HEIGHT
# - STACKS_24_HEIGHT
# - STACKS_25_HEIGHT
# - STACKS_30_HEIGHT
# - STACKING_CYCLES
# - POX_PREPARE_LENGTH
# - POX_REWARD_LENGTH
# - REWARD_RECIPIENT
# - EXIT_FROM_MONITOR