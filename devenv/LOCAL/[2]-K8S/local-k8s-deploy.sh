# [1] Apply the Kubernetes Namespaces first

kubectl apply -f ./namespaces/namespaces.yaml

# [2] Apply the Kubernetes Services (the Docker containers refer to them)

kubectl apply -f ./services/services.yaml

# [3] Apply the K8s Deployments


# i - Bitcoin
kubectl apply -f ./services/bitcoin-deployment.yaml

# ii - MariaDB
kubectl apply -f ./services/mariadb-deployment.yaml

# iii - Postgres
kubectl apply -f ./services/postgres-deployment.yaml

# TODO() WAIT FOR BTC NODE.SH
# iv - Electrs
kubectl apply -f ./services/electrs-deployment.yaml

# v - Nakamoto Signer
kubectl apply -f ./services/nakamoto-signer-deployment.yaml

# TODO() WAIT FOR BTC NODE.SH
# vi - Stacks
kubectl apply -f ./services/stacks-node-deployment.yaml

# TODO() WAIT FOR STACKS NODE.SH
# vii - Stacks API
kubectl apply -f ./services/stacks-api-deployment.yaml

# TODO() WAIT FOR STACKS API .SH
# viii - Stacks Explorer
kubectl apply -f ./services/stacks-explorer-deployment.yaml

# TODO() WAIT FOR MARIADB .SH
# ix - Mempool Backend
kubectl apply -f ./services/mempool-backend-deployment.yaml

# TODO() WAIT FOR MEMPOOL BACKEND.SH
# x - Mempool Frontend
kubectl apply -f ./services/mempool-frontend-deployment.yaml