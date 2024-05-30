#!/bin/sh

echo "BUILDING K8S CONTAINERS"

echo "[1] SET KUBERNETES CONTEXT TO `minikube`\n\n"
kubectx minikube

echo "[2] SET THE DOCKER IMAGE REGISTRY TARGET TO MINIKUBE\n\n"
eval $(minikube docker-env)


docker build -t minikube/bitcoin:v1 ./custom-k8s-docker-builds/bitcoin/docker/
docker build -t minikube/bitcoin-miner-sidecar:v1 ./custom-k8s-docker-builds/bitcoin-miner-sidecar/docker/
docker build -t minikube/stacks:v1 ./custom-k8s-docker-builds/stacks/docker/
docker build -t minikube/stacks-api:v1 ./custom-k8s-docker-builds/stacks-api/docker/
docker build -t minikube/stacks-explorer:v1 ./custom-k8s-docker-builds/stacks-explorer/docker/
docker build -t minikube/nakamoto-signer:v1 ./custom-k8s-docker-builds/nakamoto-signer/docker/
docker build -t minikube/electrs:v1 ./custom-k8s-docker-builds/electrs/docker/