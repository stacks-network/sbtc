#!/usr/bin/env bash

set -x

nginx


# Make .bitcoin dir if not exists
DOT_BITCOIN_DIR="/root/.bitcoin"
if [ ! -d "$DOT_BITCOIN_DIR" ]; then
    mkdir $DOT_BITCOIN_DIR
fi


# COPY the bitcoin.conf from the shared volume (from the init container to the DOT_BITCOIN_DIR)
SHARED_VOL_DIR="/mnt/shared"


mv "$SHARED_VOL_DIR/bitcoin.conf" "$DOT_BITCOIN_DIR"

bitcoind \
    -regtest \
    -txindex=${BTC_TXINDEX} \
    -rpcuser=${BTC_RPCUSER} \
    -rpcpassword=${BTC_RPCPASSWORD} \
    -printtoconsole=${BTC_PRINTTOCONSOLE} \
    -disablewallet=${BTC_DISABLEWALLET} \
    -rpcallowip=${BTC_RPCALLOWIP} \
    -rpcport=${BTC_RPC_PORT} \
    -server=1 \
    -conf=${DOT_BITCOIN_DIR}/bitcoin.conf