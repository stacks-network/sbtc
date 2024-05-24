#!/usr/bin/env bash

set -x

nginx

## ----------------------------------------------
## -------- [1. OLD WAY OF STARTING BTC] --------
## ----------------------------------------------
## Problems: It doesn't create the `bitcoin.conf` file in the dir: `/root/.bitcoin/bitcoin.conf`. So anytime other apps try to use the RPC creds, it doesn't work

# bitcoind \
#     -chain=${BTC_NETWORK} \
#     -txindex=${BTC_TXINDEX} \
#     -rpcuser=${BTC_RPCUSER} \
#     -rpcpassword=${BTC_RPCPASSWORD} \
#     -printtoconsole=${BTC_PRINTTOCONSOLE} \
#     -disablewallet=${BTC_DISABLEWALLET} \
#     -rpcbind=${BTC_RPCBIND} \
#     -rpcallowip=${BTC_RPCALLOWIP} \
#     -rpcport=${BTC_RPC_PORT} \
#     -server=1 \
#     -debug=1

## --------------------------------
## -------- [2. NEW WAY] ----------
## --------------------------------

## We will directly create the `bitcoin.conf` file instead of expecting bitcoind to do it for us
## Since we know this is a regtest node, we can specify that directly

DOT_BITCOIN_DIR="/root/.bitcoin"
if [ ! -d "$DOT_BITCOIN_DIR" ]; then
    mkdir $DOT_BITCOIN_DIR
fi


tee -a $DOT_BITCOIN_DIR/bitcoin.conf << END
regtest=1 #chain=regtest

[regtest]
# Accept command line and JSON-RPC commands
server=1
# Username for JSON-RPC connections
rpcuser="$BTC_RPCUSER"
# Password for JSON-RPC connections
rpcpassword="$BTC_RPCPASSWORD"

# Allow JSON-RPC connections from, by default only localhost are allowed
rpcallowip=$BTC_RPCALLOWIP

bind=$BTC_RPCBIND
rpcbind=$BTC_RPCBIND
rpcport=$BTC_RPC_PORT
dbcache=512
banscore=1
rpcthreads=256
rpcworkqueue=256
rpctimeout=100

# Accept public REST requests (default: 0)
# rest=$BTC_REST_ENABLE

# output all debug info
# debug=$BTC_LOG_DEBUG

# disablewallet=$BTC_DISABLEWALLET
disablewallet=0

# printtoconsole=$BTC_PRINTTOCONSOLE
printtoconsole=1

addresstype=legacy
changetype=legacy
fallbackfee=0.00001

# Maintain a full transaction index, used by the getrawtransaction rpc call (default: 0)
# txindex=$BTC_TXINDEX
txindex=1
END

# # ----------------------------------------------------------
# # Add auth cookie which is needed for electrs

echo "$BTC_RPCUSER:$BTC_RPCPASSWORD" > $DOT_BITCOIN_DIR/.bitcoin/regtestauth.cookie

# # ----------------------------------------------------------

# # bitcoind -chain=${BTC_NETWORK} -txindex=${BTC_TXINDEX} -rpcuser=${BTC_RPCUSER} -rpcpassword=${BTC_RPCPASSWORD} -printtoconsole=${BTC_PRINTTOCONSOLE} -disablewallet=${BTC_DISABLEWALLET} -rpcbind=${BTC_RPCBIND} -rpcallowip=${BTC_RPCALLOWIP}
# bitcoind -regtest -conf=${DOT_BITCOIN_DIR}/bitcoin.conf


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