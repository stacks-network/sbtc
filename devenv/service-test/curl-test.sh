#!/bin/bash

# Setup host info.
HOSTNAME="$1"
PORT="$2"
ENDPOINT="http://$HOSTNAME:$PORT"

# Create test constants
BLOCK_HEIGHT=123424
BITCOIN_TXID=DUMMY_TXID
BITCOIN_OUTPUT_INDEX_1=4
BITCOIN_OUTPUT_INDEX_2=3


# Wait for apigateway interface to setup.
sleep 5

# Test chainstate endpoint.
curl -X POST -d "{\"blockHash\":\"afviebuvf\", \"blockHeight\": $BLOCK_HEIGHT }" "http://$HOSTNAME:3000/chainstate" | jq
curl "$ENDPOINT/chainstate/$BLOCK_HEIGHT" | jq

# Test deposit endpoint.
curl -X POST -d "{\"bitcoinTxid\":\"$BITCOIN_TXID\",\"bitcoinTxOutputIndex\":$BITCOIN_OUTPUT_INDEX_1,\"reclaim\":\"DUMMY_RECLAIM\",\"deposit\":\"DUMMY_DEPOSIT\"}" "$ENDPOINT/deposits" | jq
curl -X POST -d "{\"bitcoinTxid\":\"$BITCOIN_TXID\",\"bitcoinTxOutputIndex\":$BITCOIN_OUTPUT_INDEX_2,\"reclaim\":\"DUMMY_RECLAIM\",\"deposit\":\"DUMMY_DEPOSIT\"}" "$ENDPOINT/deposits" | jq
curl "$ENDPOINT/deposits/$BITCOIN_TXID/$BITCOIN_OUTPUT_INDEX_1" | jq
curl "$ENDPOINT/deposits/$BITCOIN_TXID" | jq
curl "$ENDPOINT/deposits?status=PENDING" | jq

curl -X PUT -d "{\"deposits\":[{\"bitcoinTxid\":\"$BITCOIN_TXID\",\"bitcoinTxOutputIndex\":$BITCOIN_OUTPUT_INDEX_2,\"reclaim\":\"DUMMY_RECLAIM_2\"}]}" "$ENDPOINT/deposits" | jq
