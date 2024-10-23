#!/bin/sh
# Wait until bitcoin RPC is ready
echo "checking if bitcoin node is online"
until curl -f -s -o /dev/null --user devnet:devnet --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}' -H 'content-type: text/plain;' http://$BITCOIN_RPC_HOST:$BITCOIN_RPC_PORT/
do
	echo "bitcoin node is not ready, sleep two seconds"
	sleep 2
done
echo "bitcoin node is ready"

electrs --network regtest \
	--jsonrpc-import \
	--cookie "devnet:devnet" \
	--http-addr="0.0.0.0:3002" \
	--electrum-rpc-addr="0.0.0.0:60401" \
	--daemon-rpc-addr="$BITCOIN_RPC_HOST:$BITCOIN_RPC_PORT" \
	--electrum-txs-limit=2048 \
	--utxos-limit=2048 \
	--db-dir="/opt" \
	--cors="*" \
	-vv
