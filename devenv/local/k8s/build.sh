#!/bin/sh

echo "BUILDING K8S CONTAINERS"

echo "[1] SET KUBERNETES CONTEXT TO `minikube`\n\n"
kubectx minikube

echo "[2] SET THE DOCKER IMAGE REGISTRY TARGET TO MINIKUBE\n\n"
eval $(minikube docker-env)


docker build -t minikube/bitcoin:v1 ./custom-k8s-docker-builds/bitcoin/docker/
docker build -t minikube/bitcoin-miner-sidecar:v1 ./custom-k8s-docker-builds/bitcoin-miner-sidecar/docker/
