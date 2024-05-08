#!/usr/bin/env bash

set -x

#-rpcuser=${BTC_RPCUSER} -rpcpassword=${BTC_RPCPASSWORD}

# bitcoind needs creds set in the conf file for remote RPC auth
# echo '[regtest]' > ${BITCOIN_CONF}

nginx
bitcoind -chain=${BTC_NETWORK} -txindex=${BTC_TXINDEX} -rpcuser=${BTC_RPCUSER} -rpcpassword=${BTC_RPCPASSWORD} -printtoconsole=${BTC_PRINTTOCONSOLE} -disablewallet=${BTC_DISABLEWALLET} -rpcbind=${BTC_RPCBIND} -rpcallowip=${BTC_RPCALLOWIP}
