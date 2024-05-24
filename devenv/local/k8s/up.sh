# [1] Apply the Kubernetes Namespaces first
kubectl apply -f ./yamls/namespaces/namespaces.yaml

# [2] Apply the Kubernetes Services (the Docker containers refer to them)
kubectl apply -f ./yamls/services/services.yaml

# [3] Apply the K8s Deployments
# i - Bitcoin
kubectl apply -f ./yamls/deployments/bitcoin-deployment.yaml


sh ./utils/port-forward-containers.sh


echo "\033[1m ✅ K8S DEVNET RUNNING\033[0m"