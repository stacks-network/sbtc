#!/bin/bash

echo -e " -----------------------------------------------"
echo -e "| => (1) 🔬 TEST: [CHECK BITCOIN NODE IS LIVE]  |"
echo -e " -----------------------------------------------"

CHECK_BTC_LIVENESS_RESULT=$(curl -s -u "devnet:devnet" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}' -H 'content-type: text/plain;' "http://localhost:18443/" | jq)

echo -e "\nGET BLOCKCOUNT RPC:"
echo -e $CHECK_BTC_LIVENESS_RESULT | jq

BTC_LIVENESS_SUCCESS=$(echo -e $CHECK_BTC_LIVENESS_RESULT | jq -r '.error == null')
BTC_LIVENESS_SUCCESS_FRMT=$([ "$BTC_LIVENESS_SUCCESS" == "true" ] && echo -e "\033[1;32mtrue\033[0m ✅" || echo -e "\033[1;31mfalse\033[0m❌")


echo -e "\033[1mBTC_LIVENESS_SUCCESS\033[0m: $BTC_LIVENESS_SUCCESS_FRMT"
echo -e "\n"

echo -e " ------------------------------------------------------"
echo -e "| => (2) 🔬 TEST: [CHECK IF BTC MINER IS ABLE TO MINE] |"
echo -e " ------------------------------------------------------"

echo -e "\nMINE 1 BLOCK RPC:"
MINER_ADDRESS="mqVnk6NPRdhntvfm4hh9vvjiRkFDUuSYsH"
CHECK_IF_BTC_MINEABLE_RESULT=$(curl -s -u "devnet:devnet" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generatetoaddress", "params": [1, "'$MINER_ADDRESS'"]}' -H 'content-type: text/plain;' "http://localhost:18443/" | jq)

echo -e $CHECK_IF_BTC_MINEABLE_RESULT | jq

BTC_MINEABLE_SUCCESS=$(echo -e $CHECK_IF_BTC_MINEABLE_RESULT | jq -r '.error == null')
BTC_MINEABLE_SUCCESS_FRMT=$([ "$BTC_MINEABLE_SUCCESS" == "true" ] && echo -e "\033[1;32mtrue\033[0m ✅" || echo -e "\033[1;31mfalse\033[0m❌")

echo -e "\033[1mBTC_MINEABLE_SUCCESS\033[0m: $BTC_MINEABLE_SUCCESS_FRMT"
echo -e "\n"

echo -e " -----------------------------------------------"
echo -e "| => (3) 🔬 TEST: [CHECK IF POSTGRES IS READY]  |"
echo -e " -----------------------------------------------"

# PG_DOCKER_LOGS=$(docker logs postgres 2>/dev/null)

# PG_READY_SUCCESS=false
# PG_READY_SUCCESS_FRMT=$(echo -e "\033[1;31m$PG_READY_SUCCESS\033[0m❌")
# if [[ $PG_DOCKER_LOGS == *"ready to accept connections"* ]]; then
#     PG_READY_SUCCESS=true
#     PG_READY_SUCCESS_FRMT=$(echo -e "\033[1;32m$PG_READY_SUCCESS\033[0m ✅")
# fi

## DO NOT UNCOMMENT (USE THIS IF YOU WANT TO BE ABSOLUTELY SURE THAT POSTGRES WORKS)
PG_READY_SUCCESS=false
PG_READY_SUCCESS_FRMT=$(echo -e "\033[1;31m$PG_READY_SUCCESS\033[0m❌")
if (docker compose exec -it postgres-1 pg_isready); then
    PG_READY_SUCCESS=true
    PG_READY_SUCCESS_FRMT=$(echo -e "\033[1;32m$PG_READY_SUCCESS\033[0m ✅")
fi

echo -e "\033[1mPG_READY_SUCCESS\033[0m: $PG_READY_SUCCESS_FRMT"
echo -e "\n"

echo -e " -----------------------------------------------"
echo -e "| => (4) 🔬 TEST: [CHECK IF MARIADB IS READY]  |"
echo -e " -----------------------------------------------"

MARIADB_DOCKER_LOGS=$(docker compose logs mariadb 2>/dev/null)

MARIADB_READY_SUCCESS=false
MARIADB_READY_SUCCESS_FRMT=$(echo "\033[1;31m$MARIADB_READY_SUCCESS\033[0m❌")
if [[ $MARIADB_DOCKER_LOGS == *"ready for connections"* || $MARIADB_DOCKER_LOGS == *"Ready for start up"* ]]; then
    MARIADB_READY_SUCCESS=true
    echo -e "MariaDB || Ready for start up"
    MARIADB_READY_SUCCESS_FRMT=$(echo -e "\033[1;32m$MARIADB_READY_SUCCESS\033[0m ✅")
fi

echo -e "\033[1mMARIADB_READY_SUCCESS\033[0m: $MARIADB_READY_SUCCESS_FRMT"
echo -e "\n"

echo -e " ------------------------------------------------------"
echo -e "| => (5) 🔬 TEST: [CHECK IF NAKAMOTO SIGNER IS READY]  |"
echo -e " ------------------------------------------------------"


NAKAMOTO_SIGNER_DOCKER_LOGS=$(docker compose logs stacks-signer-1 2>/dev/null)

NAKAMOTO_SIGNER_READY_SUCCESS=false
NAKAMOTO_SIGNER_READY_SUCCESS_FRMT=$(echo -e "\033[1;31m$NAKAMOTO_SIGNER_READY_SUCCESS\033[0m❌")
if [[ $NAKAMOTO_SIGNER_DOCKER_LOGS == *"Signer spawned successfully"* ]]; then
    NAKAMOTO_SIGNER_READY_SUCCESS=true
    echo -e "Nakamoto Signer || Signer spawned successfully"
    NAKAMOTO_SIGNER_READY_SUCCESS_FRMT=$(echo -e "\033[1;32m$NAKAMOTO_SIGNER_READY_SUCCESS\033[0m ✅")
fi


echo -e "\033[1mNAKAMOTO_SIGNER_READY_SUCCESS\033[0m: $NAKAMOTO_SIGNER_READY_SUCCESS_FRMT"
echo -e "\n"

echo -e " --------------------------------------------------"
echo -e "| => (6) 🔬 TEST: [CHECK IF STACKS NODE IS READY]  |"
echo -e " --------------------------------------------------"

GET_STACKS_NODE_INFO_STATUS_CODE=$(curl --write-out %{http_code} --silent --output /dev/null "http://localhost:20443/v2/info")

echo -e "\nGET STACKS NODE STATUS: $GET_STACKS_NODE_INFO_STATUS_CODE"

STX_LIVENESS_SUCCESS=false
STACKS_LIVENESS_SUCCESS_FRMT=$(echo -e "\033[1;31m$STX_LIVENESS_SUCCESS\033[0m❌")

if [[ $GET_STACKS_NODE_INFO_STATUS_CODE == "200" ]]; then
    STX_LIVENESS_SUCCESS=true
    STACKS_LIVENESS_SUCCESS_FRMT=$(echo -e "\033[1;32m$STX_LIVENESS_SUCCESS\033[0m ✅")
fi


echo -e "\033[1mSTACKS_LIVENESS_SUCCESS\033[0m: $STACKS_LIVENESS_SUCCESS_FRMT"
echo -e "\n"

echo -e " ---------------------------------------------------------------"
echo -e "| => (7) 🔬 TEST: [CHECK IF STX NODE IS SYNCED WITH BTC UTXOs]  |"
echo -e " ---------------------------------------------------------------"

## (RPC APPROACH)
GET_STACKS_NODE_INFO=$(curl -s "http://localhost:20443/v2/info")

echo -e "\nGET STACKS NODE INFO:"
echo -e $GET_STACKS_NODE_INFO | jq 'del(.stackerdbs)'
echo -e "\t\t.\n\t\t.\n  \033[1;32m<<\033[0m \033[1;35mLong Output Supressed\033[0m \033[1;32m>>\033[0m \n\t\t.\n\t\t."

STX_SYNC_WITH_BTC_UTXO_SUCCESS=$(echo -e $GET_STACKS_NODE_INFO | jq -r '.stacks_tip_height != 0')
STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT=$([ "$STX_SYNC_WITH_BTC_UTXO_SUCCESS" == "true" ] && echo -e "\033[1;32mtrue\033[0m ✅" || echo -e "\033[1;31mfalse\033[0m❌")

echo -e "\033[1mSTX_SYNC_WITH_BTC_UTXO_SUCCESS\033[0m: $STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT"
echo -e "\n"

echo -e " ---------------------------------------------------------------"
echo -e "| => (8) 🔬 TEST: [CHECK STACKS API EVENT OBSERVER LIVENESS]  |"
echo -e " ---------------------------------------------------------------"

GET_STACKS_API_EVENT_OBSERVER_PING=$(curl -s "http://localhost:3700")

echo -e "\nGET STACKS API EVENT OBSERVER PING:"
echo -e $GET_STACKS_API_EVENT_OBSERVER_PING | jq

STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS=$(echo -e $GET_STACKS_API_EVENT_OBSERVER_PING | jq -r '.status == "ready"')
STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT=$([ "$STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS" == "true" ] && echo -e "\033[1;32mtrue\033[0m ✅" || echo -e "\033[1;31mfalse\033[0m❌")

echo -e "\033[1mSTACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS\033[0m: $STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT"
echo -e "\n"

echo -e " ---------------------------------------------------------------"
echo -e "| => (9) 🔬 TEST: [CHECK STACKS PUBLIC API LIVENESS]  |"
echo -e " ---------------------------------------------------------------"

GET_STACKS_PUBLIC_API_PING=$(curl -s --write-out %{http_code} --silent --output /dev/null  "http://localhost:3999/extended/")

echo -e "\nGET STACKS PUBLIC API PING:"
echo -e $GET_STACKS_PUBLIC_API_PING | jq

STACKS_PUBLIC_API_LIVENESS_SUCCESS=false
STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT=$(echo -e "\033[1;31mfalse\033[0m❌")

if [[ $GET_STACKS_PUBLIC_API_PING == "200" ]]; then
    STACKS_PUBLIC_API_LIVENESS_SUCCESS=true
    STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT=$(echo -e "\033[1;32m$STACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m ✅")
fi

echo -e "\033[1mSTACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m: $STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT"
echo -e "\n"

echo -e " -----------------------------------------------------------------"
echo -e "| => (10) 🔬 TEST: [CHECK IF STACKS-API IS CONNECTED TO POSTGRES]  |"
echo -e " -----------------------------------------------------------------"

STACKS_API_DOCKER_LOGS=$(docker compose logs stacks-api 2>/dev/null)

STACKS_API_CONNECTED_TO_PG_SUCCESS=false
STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT=$(echo -e "\033[1;31m$STACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m❌")
if [[ $STACKS_API_DOCKER_LOGS == *"PgNotifier connected"* ]]; then
    STACKS_API_CONNECTED_TO_PG_SUCCESS=true
    echo -e "Stacks-API || PgNotifier connected"
    STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT=$(echo -e "\033[1;32m$STACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m ✅")
fi

echo -e "\033[1mSTACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m: $STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT"
echo -e "\n"

echo -e "-----------------------------------------------------------------"
echo -e "|                        SUMMARY                                 |"
echo -e "-----------------------------------------------------------------"
echo -e "| \033[1mBTC_LIVENESS_SUCCESS\033[0m:                         | \t $BTC_LIVENESS_SUCCESS_FRMT |"
echo -e "| \033[1mBTC_MINEABLE_SUCCESS\033[0m:                         | \t $BTC_MINEABLE_SUCCESS_FRMT |"
echo -e "| \033[1mPG_READY_SUCCESS\033[0m:                             | \t $PG_READY_SUCCESS_FRMT |"
echo -e "| \033[1mMARIADB_READY_SUCCESS\033[0m:                        | \t $MARIADB_READY_SUCCESS_FRMT |"
echo -e "| \033[1mNAKAMOTO_SIGNER_READY_SUCCESS\033[0m:                | \t $NAKAMOTO_SIGNER_READY_SUCCESS_FRMT |"
echo -e "| \033[1mSTACKS_LIVENESS_SUCCESS\033[0m:                      | \t $STACKS_LIVENESS_SUCCESS_FRMT |"
echo -e "| \033[1mSTX_SYNC_WITH_BTC_UTXO_SUCCESS\033[0m:               | \t $STX_SYNC_WITH_BTC_UTXO_SUCCESS_FRMT |"
echo -e "| \033[1mSTACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS\033[0m:   | \t $STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS_FRMT |"
echo -e "| \033[1mSTACKS_PUBLIC_API_LIVENESS_SUCCESS\033[0m:           | \t $STACKS_PUBLIC_API_LIVENESS_SUCCESS_FRMT |"
echo -e "| \033[1mSTACKS_API_CONNECTED_TO_PG_SUCCESS\033[0m:           | \t $STACKS_API_CONNECTED_TO_PG_SUCCESS_FRMT |"
echo -e "-----------------------------------------------------------------"

if [[ $BTC_LIVENESS_SUCCESS == true \
    && $BTC_MINEABLE_SUCCESS == true \
    && $PG_READY_SUCCESS == true \
    && $MARIADB_READY_SUCCESS == true \
    && $NAKAMOTO_SIGNER_READY_SUCCESS == true \
    && $STACKS_LIVENESS_SUCCESS == true \
    && $STX_SYNC_WITH_BTC_UTXO_SUCCESS == true \
    && $STACKS_API_EVENT_OBSERVER_LIVENESS_SUCCESS == true \
    && $STACKS_PUBLIC_API_LIVENESS_SUCCESS == true \
    && $STACKS_API_CONNECTED_TO_PG_SUCCESS == true ]]; then
    exit 0
fi

exit 1
