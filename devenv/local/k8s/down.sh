
# [1] Delete the K8s deployments first
kubectl delete -f ./yamls/deployments/bitcoin-deployment.yaml

# [2] Delete the K8s services
kubectl delete -f ./yamls/services/services.yaml


sh ./utils/kill-port-forwards.sh