#!/bin/sh
set +x

# Create signer-config.toml
sudo bash -c cat <<EOF> ./config.toml
# The IP address and port where your Stacks node can be accessed. 
# The port 20443 is the default RPC endpoint for Stacks nodes. 
# Note that you must use an IP address - DNS hosts are not supported at this time.
node_host = "$STACKS_NODE_RPC_HOST:$STACKS_NODE_RPC_PORT"

# This is the location where the signer will expose an RPC endpoint for 
# receiving events from your Stacks node.
endpoint = "$SIGNER_ENDPOINT"

# Either “testnet” or “mainnet”
network = "testnet"

# this is a file path where your signer will persist data. If using Docker, 
# this must be within a volume, so that data can be persisted across restarts
db_path = "/var/stacks/signer.sqlite"

# an authentication token that is used for some HTTP requests made from the 
# signer to your Stacks node. You’ll need to use this later on when configuring 
# your Stacks node. You create this field yourself, rather than it being generated 
# with your private key.
auth_password = "$MY_HTTP_AUTH_TOKEN"

# This is the hex-encoded privateKey field from the keys you generated in the 
# previous step.
stacks_private_key = "$STACKS_PRIVATE_KEY"
EOF

stacks-signer run --config ./config.toml