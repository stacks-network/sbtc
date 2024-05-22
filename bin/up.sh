#!/bin/bash

# Save the current working directory
CURRENT_DIR=$(pwd)
CONTRACTS_DIR=$(pwd)/../contracts
subpath="sbtc/bin"

if [[ "$CURRENT_DIR" == *"$subpath"* ]]; then
    echo "Running [clarinet devnet start] in the contracts directory and then running secondary docker containers."
else
    echo "Please run this command in the sbtc/bin directory."
    exit 1
fi

cd $CONTRACTS_DIR
printf "\nRunning: primary containers using clarinet\n"
clarinet devnet start --no-dashboard &

sleep 15

cd $CURRENT_DIR
printf "\nRunning: secondary containers\n"
docker-compose up -d

sleep 5

docker network ls
docker ps -a

printf "\n\nScript completed.\n\n"