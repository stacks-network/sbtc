#!/bin/bash

# Setup host info.
HOSTNAME="$1"
PORT="$2"

ENDPOINT="http://$HOSTNAME:$PORT"

banner() {
    echo
    echo "$1"
    printf '%80s\n' | tr ' ' '-'
}

# Wait for apigateway interface to setup.
SLEEP_TIME="$3"
sleep "$SLEEP_TIME"
curl "$ENDPOINT/deposit/TRANSACTION/32" | jq

curl -X POST "$ENDPOINT/deposit" \
     -H "Content-Type: application/json" \
     -d '{
           "bitcoinTxid": "example_txid",
           "bitcoinTxOutputIndex": 0,
           "reclaimScript": "example_reclaim_script",
           "depositScript": "example_deposit_script"
         }' | jq

curl -X POST "$ENDPOINT/deposit" \
     -H "Content-Type: application/json" \
     -d '{
           "bitcoinTxid": "example_txid",
           "bitcoinTxOutputIndex": 1,
           "reclaimScript": "example_reclaim_script",
           "depositScript": "example_deposit_script"
         }' | jq

curl -X POST "$ENDPOINT/deposit" \
     -H "Content-Type: application/json" \
     -d '{
           "bitcoinTxid": "example_txid",
           "bitcoinTxOutputIndex": 4,
           "reclaimScript": "example_reclaim_script",
           "depositScript": "example_deposit_script"
         }' | jq

curl "$ENDPOINT/deposit/example_txid/0" | jq

curl "$ENDPOINT/deposit?status=pending" | jq

# Test pagination for deposits endpoint.
RESPONSE=$(curl "$ENDPOINT/deposit?status=pending&pageSize=2")
echo "$RESPONSE" | jq
NEXT_TOKEN=$(echo "$RESPONSE" | jq -r .nextToken)
curl "$ENDPOINT/deposit?status=pending&pageSize=2&nextToken=$NEXT_TOKEN" | jq

# Test pagination for deposits for transaction endpoint.
RESPONSE=$(curl "$ENDPOINT/deposit/example_txid?status=pending&pageSize=2")
echo "$RESPONSE" | jq
NEXT_TOKEN=$(echo "$RESPONSE" | jq -r .nextToken)
curl "$ENDPOINT/deposit/example_txid?status=pending&pageSize=2&nextToken=$NEXT_TOKEN" | jq

banner "Create Withdrawals Test"

curl -X POST "$ENDPOINT/withdrawal" \
     -H "Content-Type: application/json" \
     -d '{
           "requestId": 0,
           "stacksBlockHash": "example_hash",
           "stacksBlockHeight": 11,
           "recipient": "example_recipient",
           "amount": 0,
           "parameters": {
              "maxFee": 0
           }
         }' | jq

curl -X POST "$ENDPOINT/withdrawal" \
     -H "Content-Type: application/json" \
     -d '{
           "requestId": 2,
           "stacksBlockHash": "example_hash",
           "stacksBlockHeight": 12,
           "recipient": "example_recipient",
           "amount": 0,
           "parameters": {
              "maxFee": 0
           }
         }' | jq

curl -X POST "$ENDPOINT/withdrawal" \
     -H "Content-Type: application/json" \
     -d '{
           "requestId": 3,
           "stacksBlockHash": "example_hash",
           "stacksBlockHeight": 13,
           "recipient": "example_recipient",
           "amount": 0,
           "parameters": {
              "maxFee": 0
           }
         }' | jq

banner "Get Withdrawal Test"

# Get request id 2
curl "$ENDPOINT/withdrawal/2" | jq

banner "Get Withdrawals Test"

# Test pagination for deposits endpoint.
RESPONSE=$(curl "$ENDPOINT/withdrawal?status=pending&pageSize=5")
echo "$RESPONSE" | jq
NEXT_TOKEN=$(echo "$RESPONSE" | jq -r .nextToken)
curl "$ENDPOINT/withdrawal?status=pending&pageSize=2&nextToken=$NEXT_TOKEN" | jq
NEXT_TOKEN=$(echo "$RESPONSE" | jq -r .nextToken)
curl "$ENDPOINT/withdrawal?status=pending&pageSize=2&nextToken=$NEXT_TOKEN" | jq

curl -X POST "$ENDPOINT/chainstate" \
     -H "Content-Type: application/json" \
     -d '{
        "stacksBlockHeight": 3,
        "stacksBlockHash": "example_hash_1"
      }' | jq

curl "$ENDPOINT/chainstate/3" | jq

curl -X POST "$ENDPOINT/chainstate" \
     -H "Content-Type: application/json" \
     -d '{
        "stacksBlockHeight": 4,
        "stacksBlockHash": "example_hash_2"
      }' | jq

curl "$ENDPOINT/chainstate/4" | jq
curl "$ENDPOINT/chainstate/3" | jq
curl "$ENDPOINT/chainstate/2" | jq
