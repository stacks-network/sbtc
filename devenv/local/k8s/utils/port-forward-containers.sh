#!/bin/bash

echo " -----------------------------------------------------------  "
echo "|                                                           |\n"

if (echo $(kubectl wait --for=condition=progressing --timeout=5s deployment/bitcoin-regtest-deployment -n bitcoin)) | grep -q "condition met"; then
    kubectl port-forward svc/bitcoin-regtest-service 18443:18443 -n bitcoin &

    sleep 0.1
    echo "\n| [1] ⏭  Bitcoin Node is listening on localhost 📡       ✅ |"
else
    echo "\n| [1] ⏭  Unable to port-forward Bitcoin Node\n|        Please check if Bitcoin is running              🚫 |"
    echo "🚫 Unable to port-forward Bitcoin Node. Please check if 'bitcoin-regtest-deployment' is running"
fi

echo " ----------------------------------------------------------- "