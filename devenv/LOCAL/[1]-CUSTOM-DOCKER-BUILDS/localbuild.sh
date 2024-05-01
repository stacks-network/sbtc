# SET THE DOCKER RUNTIME
eval $(minikube docker-env)


# RUN DOCKER BUILD FOR ALL CONTAINERS IN PARALLEL
docker build -t local/bitcoin:v1 ./bitcoin/docker/
P1=$!
docker build -t local/bitcoin-miner-sidecar:v1 ./bitcoin-miner-sidecar/ &
P2=$!
docker build -t local/electrs:v1 ./electrs/docker/ &
P3=$!
docker build -t local/stacks:v1 ./stacks/docker/ &
P4=$!
docker build -t local/stacks-api:v1 ./stacks-api/docker/ &
P5=$!
docker build -t local/stacks-explorer:v1 ./stacks-explorer/docker/ &
P6=$!
docker build -t local/nakamoto-signer:v1 ./nakamoto-signer/docker/ &
P7=$!
wait $P1 $P2 $P3 $P4 $P5 $P6 $P7