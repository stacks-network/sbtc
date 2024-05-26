#!/bin/bash

if [ -z "$1" ]
  then
    echo "Deployment file path hasn't been supplied !! eg:  ../yamls/deployments/bitcoin-deployment.yaml"
    exit 1
fi


DEPLOYMENT_FILE_PATH=$1


kubectl wait --for=condition=available --timeout=2m -f $DEPLOYMENT_FILE_PATH