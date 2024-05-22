#!/bin/bash

# Save the current working directory
CURRENT_DIR=$(pwd)
CONTRACTS_DIR=$(pwd)/../contracts

docker-compose down
sleep 2
docker rm -f stacks-explorer.contracts.devnet
sleep 2
docker rm -f bitcoin-explorer.contracts.devnet
sleep 2
docker rm -f stacks-signer-2.contracts.devnet
sleep 2
docker rm -f stacks-signer-1.contracts.devnet
sleep 2
docker rm -f stacks-node.contracts.devnet
sleep 2
docker rm -f stacks-api.contracts.devnet
sleep 2
docker rm -f postgres.contracts.devnet
sleep 2
docker rm -f bitcoin-node.contracts.devnet
sleep 2

network_name="contracts.devnet"

# List all Docker networks, filter those with the specified name, and remove them
docker network ls --filter name=${network_name} -q | while read network_id; do
  echo "Removing network ID: $network_id"
  docker network rm $network_id
done

echo "All Docker networks named '${network_name}' have been removed."docker ps -a

docker network ls
docker ps -a

echo "Script completed."