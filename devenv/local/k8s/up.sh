#!/bin/sh


# ----------------------------------------
# [1] Apply the Kubernetes Namespaces first
kubectl apply -f ./yamls/namespaces/namespaces.yaml

# ----------------------------------------
# [2] Apply the Kubernetes Secrets
kubectl apply -f ./yamls/secrets/secrets.yaml

# ----------------------------------------
# [3] Apply the Kubernetes Services
kubectl apply -f ./yamls/services/services.yaml

# ----------------------------------------
# [4] Apply the K8s Deployments

# i - Bitcoin
kubectl apply -f ./yamls/deployments/bitcoin-deployment.yaml

# ii - Bitcoin Miner
kubectl apply -f ./yamls/deployments/bitcoin-miner-deployment.yaml


# ----------------------------------------
# Port forward all containers to localhost

SECONDS_TO_WAIT=5
echo "🕔 Waiting $SECONDS_TO_WAIT seconds for port-forwarding 🫖 🫖 🫖  :\n"

for count in $(seq 1 $SECONDS_TO_WAIT); do
    echo  "$count\033[0K\r"
    sleep 1
done

sh ./utils/port-forward-containers.sh
sleep 0.2

echo "\033[1m ✅ K8S SBTC DEVNET RUNNING\033[0m"