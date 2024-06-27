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

# delete the file first if exists
rm -rf "$DOT_BITCOIN_DIR/bitcoin.conf"

# copy over the file into the location
cp "$SHARED_VOL_DIR/bitcoin.conf" "$DOT_BITCOIN_DIR"

## Q: Why are making a bitcoin.conf file and also pass in these envs into bitcoind ?
## A: Just passing in "-conf" arg into bitcoind didn't work and threw many errors. 
##    Creating a bitcoin.conf and also explictly invoking bitcoind with the parameters worked

if [[ $BTC_NETWORK == 'mainnet' ]]; then
    bitcoind -txindex=${BTC_TXINDEX} -rpcuser=${BTC_RPCUSER} -rpcpassword=${BTC_RPCPASSWORD} -printtoconsole=${BTC_PRINTTOCONSOLE} -disablewallet=${BTC_DISABLEWALLET} -rpcallowip=${BTC_RPCALLOWIP} -rpcport=${BTC_RPC_PORT} -server=1 -conf=${DOT_BITCOIN_DIR}/bitcoin.conf
elif [[ $BTC_NETWORK == 'testnet' ]]; then
    bitcoind -testnet -txindex=${BTC_TXINDEX} -rpcuser=${BTC_RPCUSER} -rpcpassword=${BTC_RPCPASSWORD} -printtoconsole=${BTC_PRINTTOCONSOLE} -disablewallet=${BTC_DISABLEWALLET} -rpcallowip=${BTC_RPCALLOWIP} -rpcport=${BTC_RPC_PORT} -server=1 -conf=${DOT_BITCOIN_DIR}/bitcoin.conf
else
    bitcoind -regtest -txindex=${BTC_TXINDEX} -rpcuser=${BTC_RPCUSER} -rpcpassword=${BTC_RPCPASSWORD} -printtoconsole=${BTC_PRINTTOCONSOLE} -disablewallet=${BTC_DISABLEWALLET} -rpcallowip=${BTC_RPCALLOWIP} -rpcport=${BTC_RPC_PORT} -server=1 -conf=${DOT_BITCOIN_DIR}/bitcoin.conf
fi