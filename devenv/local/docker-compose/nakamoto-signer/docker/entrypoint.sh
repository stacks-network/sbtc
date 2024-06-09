#!/bin/sh
set +x

# Create signer-config.toml
tee -a ./config.toml << END
node_host = "$STACKS_NODE_RPC_HOST:$STACKS_NODE_RPC_PORT"
endpoint = "$SIGNER_ENDPOINT"
network = "testnet"

# this is a file path where your signer will persist data. If using Docker, 
# this must be within a volume, so that data can be persisted across restarts
db_path = "$SIGNER_DB_PATH"

# an authentication token that is used for some HTTP requests made from the 
# signer to your Stacks node. You'll need to use this later on when configuring 
# your Stacks node. You create this field yourself, rather than it being generated 
# with your private key.
auth_password = "$MY_HTTP_AUTH_TOKEN"

# This is the hex-encoded privateKey field from the keys you generated in the 
# previous step.
stacks_private_key = "$STACKS_PRIVATE_KEY"
END

stacks-signer run --config ./config.toml