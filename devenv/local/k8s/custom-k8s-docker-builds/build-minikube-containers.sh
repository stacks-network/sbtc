echo "--- SET KUBERENTES CONTEXT TO `minikube` ---\n\n"
kubectx minikube

echo "--- SET THE DOCKER RUNTIME ---\n\n"
eval $(minikube docker-env)


docker build -t minikube/bitcoin:v1 ./bitcoin/docker/
docker build -t minikube/bitcoin-miner-sidecar:v1 ./bitcoin-miner-sidecar/docker/
docker build -t minikube/stacks:v1 ./stacks/docker/
docker build -t minikube/nakamoto-signer:v1 ./nakamoto-signer/docker/
docker build -t minikube/stacks-api:v1 ./stacks-api/docker/
docker build -t minikube/stacks-explorer:v1 ./stacks-explorer/docker/