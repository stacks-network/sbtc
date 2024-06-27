#!/bin/bash

# Setup host info.
HOSTNAME="$1"
PORT="$2"
SLEEP_TIME="$3"

ENDPOINT="http://$HOSTNAME:$PORT"

# Create test constants
BLOCK_HEIGHT=123424
BITCOIN_TXID=DUMMY_TXID
BITCOIN_OUTPUT_INDEX_1=4
BITCOIN_OUTPUT_INDEX_2=3

# Wait for apigateway interface to setup.
sleep "$SLEEP_TIME"

# Test chainstate endpoint.
curl -X POST -d "{\"blockHash\":\"afviebuvf\", \"blockHeight\": $BLOCK_HEIGHT }" "http://$HOSTNAME:3000/chainstate" | jq
curl "$ENDPOINT/chainstate/$BLOCK_HEIGHT" | jq

# Test deposit endpoint.
curl -X POST -d "{\"bitcoinTxid\":\"$BITCOIN_TXID\",\"bitcoinTxOutputIndex\":$BITCOIN_OUTPUT_INDEX_1,\"reclaim\":\"DUMMY_RECLAIM_1\",\"deposit\":\"DUMMY_DEPOSIT_1\"}" "$ENDPOINT/deposits" | jq
curl -X POST -d "{\"bitcoinTxid\":\"$BITCOIN_TXID\",\"bitcoinTxOutputIndex\":$BITCOIN_OUTPUT_INDEX_2,\"reclaim\":\"DUMMY_RECLAIM_2\",\"deposit\":\"DUMMY_DEPOSIT_2\"}" "$ENDPOINT/deposits" | jq
curl "$ENDPOINT/deposits/$BITCOIN_TXID/$BITCOIN_OUTPUT_INDEX_1" | jq
curl "$ENDPOINT/deposits/$BITCOIN_TXID" | jq

FIRST_RESULT=$(curl "$ENDPOINT/deposits/$BITCOIN_TXID?maxResults=1")
echo "$FIRST_RESULT" | jq
NEXT_TOKEN=$(echo "$FIRST_RESULT" | jq -r ".nextToken")
SECOND_RESULT=$(curl "$ENDPOINT/deposits/$BITCOIN_TXID?&maxResults=1&nextToken=$NEXT_TOKEN")
echo "$SECOND_RESULT" | jq
NEXT_TOKEN=$(echo "$SECOND_RESULT" | jq -r ".nextToken")
echo "Next token: $NEXT_TOKEN"
THIRD_RESULT=$(curl "$ENDPOINT/deposits/$BITCOIN_TXID?maxResults=1&nextToken=$NEXT_TOKEN")
echo "$THIRD_RESULT" | jq

curl "$ENDPOINT/deposits?status=PENDING" | jq

FIRST_RESULT=$(curl "$ENDPOINT/deposits?status=PENDING&maxResults=1")
echo "$FIRST_RESULT" | jq
NEXT_TOKEN=$(echo "$FIRST_RESULT" | jq -r ".nextToken")
echo "Next token: $NEXT_TOKEN"
SECOND_RESULT=$(curl "$ENDPOINT/deposits?status=PENDING&maxResults=1&nextToken=$NEXT_TOKEN")
echo "$SECOND_RESULT" | jq
NEXT_TOKEN=$(echo "$SECOND_RESULT" | jq -r ".nextToken")
echo "Next token: $NEXT_TOKEN"
THIRD_RESULT=$(curl "$ENDPOINT/deposits?status=PENDING&maxResults=1&nextToken=$NEXT_TOKEN")
echo "$THIRD_RESULT" | jq

curl -X PUT -d "{\"deposits\":[{\"bitcoinTxid\":\"$BITCOIN_TXID\",\"bitcoinTxOutputIndex\":$BITCOIN_OUTPUT_INDEX_2,\"reclaim\":\"DUMMY_RECLAIM_2\"}]}" "$ENDPOINT/deposits" | jq
