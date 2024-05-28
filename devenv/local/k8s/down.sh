#!/bin/sh

sh ./utils/kill-port-forwards.sh


# [1] Delete the K8s deployments first
kubectl delete -f ./yamls/deployments/bitcoin-deployment.yaml
kubectl delete -f ./yamls/deployments/bitcoin-miner-deployment.yaml

# [2] Delete the K8s services
kubectl delete -f ./yamls/services/services.yaml

# [3] Delete the K8s secrets
kubectl delete -f ./yamls/secrets/secrets.yaml
