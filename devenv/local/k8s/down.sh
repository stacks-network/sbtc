#!/bin/sh

sh ./utils/kill-port-forwards.sh


# [1] Delete the K8s deployments first
kubectl delete -f ./yamls/deployments/bitcoin-deployment.yaml
kubectl delete -f ./yamls/deployments/bitcoin-miner-deployment.yaml
kubectl delete -f ./yamls/deployments/postgres-deployment.yaml
kubectl delete -f ./yamls/deployments/nakamoto-signer-deployment.yaml
kubectl delete -f ./yamls/deployments/stacks-deployment.yaml
kubectl delete -f ./yamls/deployments/stacks-api-deployment.yaml
kubectl delete -f ./yamls/deployments/stacks-explorer-deployment.yaml
kubectl delete -f ./yamls/deployments/mariadb-deployment.yaml
kubectl delete -f ./yamls/deployments/electrs-deployment.yaml
kubectl delete -f ./yamls/deployments/mempool-backend-deployment.yaml
kubectl delete -f ./yamls/deployments/mempool-frontend-deployment.yaml

# [2] Delete the K8s services
kubectl delete -f ./yamls/services/services.yaml

# [3] Delete the K8s secrets
kubectl delete -f ./yamls/secrets/secrets.yaml
