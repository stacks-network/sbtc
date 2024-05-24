echo "--- SET KUBERENTES CONTEXT TO `minikube` ---\n\n"
kubectx minikube

echo "--- SET THE DOCKER RUNTIME ---\n\n"
eval $(minikube docker-env)


docker build -t minikube/bitcoin:v1 ./bitcoin/docker/
docker build -t minikube/bitcoin-miner-sidecar:v1 ./bitcoin-miner-sidecar/docker/