#!/bin/bash


echo " -----------------------------------------------"
echo "| => (1) 🔬 TEST: [CHECK BITCOIN NODE IS LIVE]  |"
echo " -----------------------------------------------"


CHECK_BTC_LIVENESS_RESULT=$(curl -s -u "devnet:devnet" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}' -H 'content-type: text/plain;' "http://localhost:18443/" | jq)

echo "\nGET BLOCKCOUNT RPC:"
echo $CHECK_BTC_LIVENESS_RESULT | jq


BTC_LIVE_CHECK=$(echo $CHECK_BTC_LIVENESS_RESULT | jq -r '.error == null')

BTC_LIVENESS_SUCCESS=false
BTC_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;31m$BTC_LIVENESS_SUCCESS\033[0m❌")
if [[ $BTC_LIVE_CHECK == "true" ]]; then
    BTC_LIVENESS_SUCCESS=true
    BTC_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;32m$BTC_LIVENESS_SUCCESS\033[0m ✅")
fi

echo "\033[1mBTC_LIVENESS_SUCCESS\033[0m: $BTC_LIVENESS_SUCCESS_FRMT"
echo "\n"



echo " ------------------------------------------------------"
echo "| => (2) 🔬 TEST: [CHECK IF BTC MINER IS ABLE TO MINE] |"
echo " ------------------------------------------------------"


echo "\nMINE 1 BLOCK RPC:"
MINER_ADDRESS="mqVnk6NPRdhntvfm4hh9vvjiRkFDUuSYsH"
CHECK_IF_BTC_MINEABLE_RESULT=$(curl -s -u "devnet:devnet" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generatetoaddress", "params": [1, "'$MINER_ADDRESS'"]}' -H 'content-type: text/plain;' "http://localhost:18443/" | jq)

echo $CHECK_IF_BTC_MINEABLE_RESULT | jq


BTC_MINE_CHECK=$(echo $CHECK_IF_BTC_MINEABLE_RESULT | jq -r '.error == null')

BTC_MINEABLE_SUCCESS=false
BTC_MINEABLE_SUCCESS_FRMT=$(echo "\033[1;31m$BTC_MINEABLE_SUCCESS\033[0m❌")
if [[ $BTC_MINE_CHECK == "true" ]]; then
    BTC_MINEABLE_SUCCESS=true
    BTC_MINEABLE_SUCCESS_FRMT=$(echo "\033[1;32m$BTC_MINEABLE_SUCCESS\033[0m ✅")
fi



echo "\033[1mBTC_MINEABLE_SUCCESS\033[0m: $BTC_MINEABLE_SUCCESS_FRMT"
echo "\n"


echo " -----------------------------------------------"
echo "| => (3) 🔬 TEST: [CHECK IF POSTGRES IS READY]  |"
echo " -----------------------------------------------"


PG_READY_SUCCESS=false
PG_READY_SUCCESS_FRMT=$(echo "\033[1;31m$PG_READY_SUCCESS\033[0m❌")
if (pg_isready -h localhost -p 5432 -U postgres); then
    PG_READY_SUCCESS=true
    PG_READY_SUCCESS_FRMT=$(echo "\033[1;32m$PG_READY_SUCCESS\033[0m ✅")
fi


echo "\033[1mPG_READY_SUCCESS\033[0m: $PG_READY_SUCCESS_FRMT"
echo "\n"



echo " ------------------------------------------------------"
echo "| => (4) 🔬 TEST: [CHECK IF NAKAMOTO SIGNER IS READY]  |"
echo " ------------------------------------------------------"

NAKAMOTO_SIGNER_POD_NAME=$(kubectl get pods --selector=app=nakamoto-signer -o json -n sbtc-signer | jq -r '.items[].metadata.name')
NAKAMOTO_SIGNER_LOGS=$(kubectl logs $NAKAMOTO_SIGNER_POD_NAME -n sbtc-signer 2>/dev/null)

echo "NAKAMOTO_SIGNER_LOGS:  $NAKAMOTO_SIGNER_LOGS"
NAKAMOTO_SIGNER_READY_SUCCESS=false
NAKAMOTO_SIGNER_READY_SUCCESS_FRMT=$(echo "\033[1;31m$NAKAMOTO_SIGNER_READY_SUCCESS\033[0m❌")
if [[ $NAKAMOTO_SIGNER_LOGS == *"Signer spawned successfully"* ]]; then
    NAKAMOTO_SIGNER_READY_SUCCESS=true
    echo "Nakamoto Signer || Signer spawned successfully"
    NAKAMOTO_SIGNER_READY_SUCCESS_FRMT=$(echo "\033[1;32m$NAKAMOTO_SIGNER_READY_SUCCESS\033[0m ✅")
fi


echo "\033[1mNAKAMOTO_SIGNER_READY_SUCCESS\033[0m: $NAKAMOTO_SIGNER_READY_SUCCESS_FRMT"
echo "\n"



echo " --------------------------------------------------"
echo "| => (5) 🔬 TEST: [CHECK IF STACKS NODE IS READY]  |"
echo " --------------------------------------------------"


GET_STACKS_NODE_INFO_STATUS_CODE=$(curl --write-out %{http_code} --silent --output /dev/null "http://localhost:20443/v2/info")


echo "\nGET STACKS NODE STATUS: $GET_STACKS_NODE_INFO_STATUS_CODE"

STX_LIVENESS_SUCCESS=false 
STACKS_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;31m$STX_LIVENESS_SUCCESS\033[0m❌")

if [[ $GET_STACKS_NODE_INFO_STATUS_CODE == "200" ]]; then
    STX_LIVENESS_SUCCESS=true
    STACKS_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;32m$STX_LIVENESS_SUCCESS\033[0m ✅")
fi


echo "\033[1mSTACKS_LIVENESS_SUCCESS\033[0m: $STACKS_LIVENESS_SUCCESS_FRMT"
echo "\n"



echo " ---------------------------------------------------------------"
echo "| => (6) 🔬 TEST: [CHECK IF STX NODE IS SYNCED WITH BTC UTXOs]  |"
echo " ---------------------------------------------------------------"


## (RPC APPROACH)
GET_STACKS_NODE_INFO=$(curl -s "http://localhost:20443/v2/info")

echo "\nGET STACKS NODE INFO:"
echo $GET_STACKS_NODE_INFO | jq 'del(.stackerdbs)'
echo "\t\t.\n\t\t.\n  \033[1;32m<<\033[0m \033[1;35mLong Output Supressed\033[0m \033[1;32m>>\033[0m \n\t\t.\n\t\t."

STX_SYNC_CHECK=$(echo $GET_STACKS_NODE_INFO | jq -r '.stacks_tip_height != 0')


STX_SYNC_WITH_BTC_UTXO_SUCCESS=false
STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT=$(echo "\033[1;31m$STX_SYNC_WITH_BTC_UTXO_SUCCESS\033[0m❌")
if [[ $STX_SYNC_CHECK == "true" ]]; then
    STX_SYNC_WITH_BTC_UTXO_SUCCESS=true
    STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT=$(echo "\033[1;32m$STX_SYNC_WITH_BTC_UTXO_SUCCESS\033[0m ✅")
fi


echo "\033[1mSTX_SYNC_WITH_BTC_UTXO_SUCCESS\033[0m: $STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT"
echo "\n"


echo " ---------------------------------------------------------------"
echo "| => (7) 🔬 TEST: [CHECK STACKS API EVENT OBSERVER LIVENESS]    |"
echo " ---------------------------------------------------------------"


GET_STACKS_API_EVENT_OBSERVER_PING=$(curl -s "http://localhost:3700")


echo "\nGET STACKS API EVENT OBSERVER PING:"
echo $GET_STACKS_API_EVENT_OBSERVER_PING | jq


STACKS_API_EO_CHECK=$(echo $GET_STACKS_API_EVENT_OBSERVER_PING | jq -r '.status == "ready"')

STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS=false
STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;31m$STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS\033[0m❌")
if [[ $STACKS_API_EO_CHECK == "true" ]]; then
    STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS=true
    STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;32m$STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS\033[0m ✅")
fi


echo "\033[1mSTACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS\033[0m: $STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT"
echo "\n"







echo " ---------------------------------------------------------------"
echo "| => (8) 🔬 TEST: [CHECK STACKS PUBLIC API LIVENESS]            |"
echo " ---------------------------------------------------------------"


GET_STACKS_PUBLIC_API_PING=$(curl -s --write-out %{http_code} --silent --output /dev/null  "http://localhost:3999/extended/")


echo "\nGET STACKS PUBLIC API PING:"
echo $GET_STACKS_PUBLIC_API_PING | jq


STACKS_PUBLIC_API_LIVENESS_SUCCESS=false
STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;31m$STACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m❌")


if [[ $GET_STACKS_PUBLIC_API_PING == "200" ]]; then
    STACKS_PUBLIC_API_LIVENESS_SUCCESS=true
    STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT=$(echo "\033[1;32m$STACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m ✅")
fi


echo "\033[1mSTACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m: $STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT"
echo "\n"






echo " -----------------------------------------------------------------"
echo "| => (9) 🔬 TEST: [CHECK IF STACKS-API IS CONNECTED TO POSTGRES]  |"
echo " -----------------------------------------------------------------"


STACKS_API_POD_NAME=$(kubectl get pods --selector=app=stacks-api -o json -n sbtc-signer | jq -r '.items[].metadata.name')

STACKS_API_LOGS=$(kubectl logs $STACKS_API_POD_NAME -n sbtc-signer 2>/dev/null)


STACKS_API_CONNECTED_TO_PG_SUCCESS=false
STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT=$(echo "\033[1;31m$STACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m❌")
if [[ $STACKS_API_LOGS == *"PgNotifier connected"* ]]; then
    STACKS_API_CONNECTED_TO_PG_SUCCESS=true
    echo "Stacks-API || PgNotifier connected"
    STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT=$(echo "\033[1;32m$STACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m ✅")
fi


echo "\033[1mSTACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m: $STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT"
echo "\n"


echo " -----------------------------------------------"
echo "| => (10) 🔬 TEST: [CHECK IF MARIADB IS READY]  |"
echo " -----------------------------------------------"

MARIADB_POD_NAME=$(kubectl get pods --selector=app=mariadb -o json -n sbtc-signer | jq -r '.items[].metadata.name')

MARIADB_LOGS=$(kubectl logs $MARIADB_POD_NAME -n sbtc-signer 2>/dev/null)

MARIADB_READY_SUCCESS=false
MARIADB_READY_SUCCESS_FRMT=$(echo "\033[1;31m$MARIADB_READY_SUCCESS\033[0m❌")
if [[ $MARIADB_LOGS == *"ready for connections"* || $MARIADB_LOGS == *"Ready for start up"* ]]; then
    MARIADB_READY_SUCCESS=true
    echo "MariaDB || Ready for start up"
    MARIADB_READY_SUCCESS_FRMT=$(echo "\033[1;32m$MARIADB_READY_SUCCESS\033[0m ✅")
fi



echo "\033[1mMARIADB_READY_SUCCESS\033[0m: $MARIADB_READY_SUCCESS_FRMT"
echo "\n"



echo "------------------------------------------------------------------"
echo "|                        SUMMARY                                 |"
echo "------------------------------------------------------------------"
echo "| \033[1mBTC_LIVENESS_SUCCESS\033[0m:                         | \t $BTC_LIVENESS_SUCCESS_FRMT |"
echo "| \033[1mBTC_MINEABLE_SUCCESS\033[0m:                         | \t $BTC_MINEABLE_SUCCESS_FRMT |"
echo "| \033[1mPG_READY_SUCCESS\033[0m:                             | \t $PG_READY_SUCCESS_FRMT |"
echo "| \033[1mNAKAMOTO_SIGNER_READY_SUCCESS\033[0m:                | \t $NAKAMOTO_SIGNER_READY_SUCCESS_FRMT |"
echo "| \033[1mSTX_LIVENESS_SUCCESS\033[0m:                         | \t $STACKS_LIVENESS_SUCCESS_FRMT |"
echo "| \033[1mSTX_SYNC_WITH_BTC_UTXO_SUCCESS\033[0m:               | \t $STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT |"
echo "| \033[1mSTACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS\033[0m:   | \t $STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT |"
echo "| \033[1mSTACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m:           | \t $STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT |"
echo "| \033[1mSTACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m:           | \t $STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT |"
echo "| \033[1mMARIADB_READY_SUCCESS\033[0m:                        | \t $MARIADB_READY_SUCCESS_FRMT |"
echo "------------------------------------------------------------------"

if [[ $BTC_LIVENESS_SUCCESS == true \
    && $BTC_MINEABLE_SUCCESS == true \
    && $PG_READY_SUCCESS == true \
    && $NAKAMOTO_SIGNER_READY_SUCCESS == true \
    && $STX_LIVENESS_SUCCESS == true \
    && $STX_SYNC_WITH_BTC_UTXO_SUCCESS == true \
    && $STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS == true \
    && $STACKS_PUBLIC_API_LIVENESS_SUCCESS == true \
    && $STACKS_API_CONNECTED_TO_PG_SUCCESS == true \
    && $MARIADB_READY_SUCCESS == true \
    ]]; then
    exit 0
fi

exit 1