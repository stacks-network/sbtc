#!/bin/bash

# Setup host info.
HOSTNAME="$1"
PORT="$2"

ENDPOINT="http://$HOSTNAME:$PORT"

# Wait for apigateway interface to setup.
SLEEP_TIME="$3"
sleep "$SLEEP_TIME"
curl "$ENDPOINT/deposit/TRANSACTION/32" | jq
