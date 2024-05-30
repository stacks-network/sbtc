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

# Bitcoin
kubectl apply -f ./yamls/deployments/bitcoin-deployment.yaml

# Bitcoin Miner
kubectl apply -f ./yamls/deployments/bitcoin-miner-deployment.yaml



# Postgres
kubectl apply -f ./yamls/deployments/postgres-deployment.yaml

# Mariadb
kubectl apply -f ./yamls/deployments/mariadb-deployment.yaml

# Nakamoto Signer
kubectl apply -f ./yamls/deployments/nakamoto-signer-deployment.yaml



# WAIT FOR BTC NODE
kubectl wait --for=condition=available --timeout=15s -f ./yamls/deployments/bitcoin-deployment.yaml
# Stacks Node
kubectl apply -f ./yamls/deployments/stacks-deployment.yaml
# Electrum
kubectl apply -f ./yamls/deployments/electrs-deployment.yaml




# WAIT FOR STACKS NODE
kubectl wait --for=condition=available --timeout=30s -f ./yamls/deployments/postgres-deployment.yaml
kubectl wait --for=condition=available --timeout=30s -f ./yamls/deployments/stacks-deployment.yaml
# Stacks API
kubectl apply -f ./yamls/deployments/stacks-api-deployment.yaml


# WAIT FOR STACKS API
kubectl wait --for=condition=available --timeout=30s -f ./yamls/deployments/stacks-api-deployment.yaml
# Stacks Explorer
kubectl apply -f ./yamls/deployments/stacks-explorer-deployment.yaml



# WAIT FOR MariaDB
kubectl wait --for=condition=available --timeout=30s -f ./yamls/deployments/mariadb-deployment.yaml
kubectl wait --for=condition=available --timeout=30s -f ./yamls/deployments/electrs-deployment.yaml
# Mempool Backend
kubectl apply -f ./yamls/deployments/mempool-backend-deployment.yaml


# WAIT FOR MEMPOOL BACKEND
kubectl wait --for=condition=available --timeout=30s -f ./yamls/deployments/mempool-backend-deployment.yaml
kubectl apply -f ./yamls/deployments/mempool-frontend-deployment.yaml

# ----------------------------------------
# Add a small pause for all deployments to get going (otherwise some tests will fail since it's searching in logs)

SECONDS_TO_WAIT=5
echo "🕔 Waiting $SECONDS_TO_WAIT seconds for Deployments... 🫖 🫖 🫖  :\n"

for count in $(seq 1 $SECONDS_TO_WAIT); do
    echo  "$count\033[0K\r"
    sleep 1
done


echo "\033[1m ✅ K8S SBTC DEVNET RUNNING\033[0m"