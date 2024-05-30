#!/bin/bash

pf_helper() {
    local deployment_name
    local service_name
    local service_port_localmachine
    local service_port_container
    local namespace
    local workload_nickname
    local counter


    deployment_name=$1
    service_name=$2
    service_port_localmachine=$3
    service_port_container=$4
    namespace=$5
    workload_nickname=$6
    counter=$7

    echo "|                                                           |\n"

    if (echo $(kubectl wait --for=condition=progressing --timeout=5s "deployment/$deployment_name" -n "$namespace" )) | grep -q "condition met"; then
        kubectl port-forward "svc/$service_name" "$service_port_localmachine:$service_port_container" -n "$namespace" &

        sleep 0.2
        echo "\n [$counter] ✅ ⏭  $workload_nickname is listening on localhost 📡 "
        echo "\n|                                                           |"
        # echo "\n-----------------------------------------------------------"
    else
        echo "\n [$counter] 🚫 ⏭  Unable to port-forward $workload_nickname\n\n      Please check if $deployment_name is running"
        echo "\n|                                                           |"
    fi

    echo " ----------------------------------------------------------- "
}




echo " -----------------------------------------------------------  "

pf_helper "bitcoin-regtest-deployment" "bitcoin-regtest-service" "18443" "18443" "sbtc-signer" "Bitcoin Node" "1"

pf_helper "nakamoto-signer-deployment" "nakamoto-signer-service" "30000" "30000" "sbtc-signer" "Nakamoto Signer" "2"

pf_helper "stacks-node-deployment" "stacks-node-service" "20443" "20443" "sbtc-signer" "Stacks Node" "3"

pf_helper "stacks-api-deployment" "stacks-api-service" "3999" "3999" "sbtc-signer" "Stacks API Public Endpoint" "4"

pf_helper "stacks-api-deployment" "stacks-api-service" "3700" "3700" "sbtc-signer" "Stacks API Event Observer" "5"

pf_helper "postgres-deployment" "postgres-service" "5432" "5432" "sbtc-signer" "Postgres" "6"

pf_helper "stacks-explorer-deployment" "stacks-explorer-service" "3020" "3000" "sbtc-signer" "Stacks Explorer" "7"

pf_helper "electrs-deployment" "electrs-service" "60401" "60401" "sbtc-signer" "Electrs" "8"

pf_helper "mariadb-deployment" "mariadb-service" "3306" "3306" "sbtc-signer" "MariaDB" "9"

pf_helper "mempool-backend-deployment" "mempool-backend-service" "8999" "8999" "sbtc-signer" "Mempool Backend" "10"

pf_helper "mempool-frontend-deployment" "mempool-frontend-service" "8083" "8083" "sbtc-signer" "Mempool Frontend" "11"

