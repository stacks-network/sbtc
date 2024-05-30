#!/bin/sh
set +x

# COPY the config.toml from the shared volume (from the init container to the current dir)
SHARED_VOL_DIR="/mnt/shared"


# delete the file first if exists
rm -rf "/config.toml"


cp "$SHARED_VOL_DIR/config.toml" "/"

stacks-node start --config /config.toml