#!/bin/bash


echo " -----------------------------------------------"
echo "| => (1) 🔬 TEST: [CHECK BITCOIN NODE IS LIVE]  |"
echo " -----------------------------------------------"


CHECK_BTC_LIVENESS_RESULT=$(curl -s -u "devnet:devnet" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}' -H 'content-type: text/plain;' "http://localhost:18443/" | jq)

echo "\nGET BLOCKCOUNT RPC:"
echo $CHECK_BTC_LIVENESS_RESULT | jq

BTC_LIVENESS_SUCCESS=$(echo $CHECK_BTC_LIVENESS_RESULT | jq -r '.error == null')
BTC_LIVENESS_SUCCESS_FRMT=$([ "$BTC_LIVENESS_SUCCESS" == "true" ] && echo "\033[1;32m$BTC_LIVENESS_SUCCESS\033[0m ✅" || echo "\033[1;31m$BTC_LIVENESS_SUCCESS\033[0m❌") 


echo "\033[1mBTC_LIVENESS_SUCCESS\033[0m: $BTC_LIVENESS_SUCCESS_FRMT"
echo "\n"



echo " ------------------------------------------------------"
echo "| => (2) 🔬 TEST: [CHECK IF BTC MINER IS ABLE TO MINE] |"
echo " ------------------------------------------------------"


echo "\nMINE 1 BLOCK RPC:"
MINER_ADDRESS="mqVnk6NPRdhntvfm4hh9vvjiRkFDUuSYsH"
CHECK_IF_BTC_MINEABLE_RESULT=$(curl -s -u "devnet:devnet" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generatetoaddress", "params": [1, "'$MINER_ADDRESS'"]}' -H 'content-type: text/plain;' "http://localhost:18443/" | jq)

echo $CHECK_IF_BTC_MINEABLE_RESULT | jq

BTC_MINEABLE_SUCCESS=$(echo $CHECK_IF_BTC_MINEABLE_RESULT | jq -r '.error == null')
BTC_MINEABLE_SUCCESS_FRMT=$([ "$BTC_MINEABLE_SUCCESS" == "true" ] && echo "\033[1;32m$BTC_MINEABLE_SUCCESS\033[0m ✅" || echo "\033[1;31m$BTC_MINEABLE_SUCCESS\033[0m❌") 


echo "\033[1mBTC_MINEABLE_SUCCESS\033[0m: $BTC_MINEABLE_SUCCESS_FRMT"
echo "\n"


echo "-----------------------------------------------------------------"
echo "|                        SUMMARY                                 |"
echo "-----------------------------------------------------------------"
echo "| \033[1mBTC_LIVENESS_SUCCESS\033[0m:                         | \t $BTC_LIVENESS_SUCCESS_FRMT |"
echo "| \033[1mBTC_MINEABLE_SUCCESS\033[0m:                         | \t $BTC_MINEABLE_SUCCESS_FRMT |"
echo "-----------------------------------------------------------------"

if [[ $BTC_LIVENESS_SUCCESS == true \
    && $BTC_MINEABLE_SUCCESS == true  ]]; then
    exit 0
fi

exit 1