https://stackoverflow.com/questions/54256980/kubernetes-pod-deployment-while-passing-args-to-container

https://stackoverflow.com/questions/48403480/running-a-shell-script-to-initialize-pods-in-kubernetes-initializing-my-db-clus


https://bitcoin.stackexchange.com/questions/116645/mempool-docker-unable-to-connect-to-electrum-server


docker build -t minikube/electrs:v1 ./electrs/docker/
docker build -t minikube/nakamoto-signer:v1 ./nakamoto-signer/docker/
docker build -t minikube/stacks:v1 ./stacks/docker/
docker build -t minikube/stacks-api:v1 ./stacks-api/docker/
docker build -t minikube/stacks-explorer:v1 ./stacks-explorer/docker/
