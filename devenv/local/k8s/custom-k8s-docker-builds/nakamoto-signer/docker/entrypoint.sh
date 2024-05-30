#!/bin/sh
set +x


SHARED_VOL_DIR="/mnt/shared"


# delete the file first if exists
rm -rf "/config.toml"


# COPY the config.toml from the shared volume (from the init container to the current dir)
cp "$SHARED_VOL_DIR/config.toml" "/"


stacks-signer run --config ./config.toml