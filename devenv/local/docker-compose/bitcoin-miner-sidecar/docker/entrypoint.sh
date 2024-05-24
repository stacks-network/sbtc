#!/bin/sh
# Wait until bitcoin RPC is ready

RPC_ENDPOINT=http://$BITCOIN_RPC_HOST:$BITCOIN_RPC_PORT/


echo "checking if bitcoin node is online"

until curl -f -s -o /dev/null -u "$BTC_RPCUSER:$BTC_RPCPASSWORD" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}' -H 'content-type: text/plain;' "$RPC_ENDPOINT"
do
	echo "bitcoin node is not ready, sleep two seconds"
	sleep 2
done
echo "bitcoin node is ready"

echo "--> Create a named 'legacy' wallet named '' -->"
curl -u "$BTC_RPCUSER:$BTC_RPCPASSWORD" --data-binary \
	'{ "jsonrpc": "1.0", "id": "curltest", "method": "createwallet", "params": { "wallet_name":"", "descriptors":false }}' \
	-H 'content-type: text/plain;' "$RPC_ENDPOINT"

echo "==> main bitcoin wallet created\n\n"


echo "--> Import miner address -->"
curl -u "$BTC_RPCUSER:$BTC_RPCPASSWORD" -d '{"jsonrpc":"1.0","id":"curltext","method":"importaddress","params":["'$MINER_ADDRESS'","",false]}' -H 'content-type:text/plain;' "$RPC_ENDPOINT"
echo "==> Miner address ($MINER_ADDRESS) has been imported\n\n"


echo "--> Mine the first N blocks -->"
curl -u "$BTC_RPCUSER:$BTC_RPCPASSWORD" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generatetoaddress", "params": ['$INIT_BTC_BLOCKS', "'$MINER_ADDRESS'"]}' -H 'content-type: text/plain;' "$RPC_ENDPOINT"
echo "=> mined initial blocks \n\n"


# Mine a single block every 10 seconds
while true
do
	curl -u "$BTC_RPCUSER:$BTC_RPCPASSWORD" --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generatetoaddress", "params": [1, "'$MINER_ADDRESS'"]}' -H 'content-type: text/plain;' "$RPC_ENDPOINT"
	echo "mined a single block"
	sleep ${BTC_BLOCK_GEN_TIME}
done