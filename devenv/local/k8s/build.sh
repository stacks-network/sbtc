echo "BUILDING K8S CONTAINERS"

echo "[1] --- SET KUBERENTES CONTEXT TO `minikube` ---\n\n"
kubectx minikube

echo "[2] --- SET THE DOCKER RUNTIME ---\n\n"
eval $(minikube docker-env)


docker build -t minikube/bitcoin:v1 ./custom-k8s-docker-builds/bitcoin/docker/
docker build -t minikube/bitcoin-miner-sidecar:v1 ./custom-k8s-docker-builds/bitcoin-miner-sidecar/docker/

# sh ./custom-k8s-docker-builds/build-minikube-containers.sh