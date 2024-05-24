#!/bin/bash

kubectl wait --for=condition=available --timeout=2m deployment/bitcoin-regtest-deployment -n bitcoin

kubectl port-forward svc/bitcoin-regtest-service 18443:18443 -n bitcoin &


echo "\n\nPort Forwarding to localhost"
sleep 1
echo "."
sleep 1
echo "."
sleep 1
echo "."
sleep 1
echo "."
