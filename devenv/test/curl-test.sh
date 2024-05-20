#!/bin/bash

apt-get -y update
apt-get -y install curl jq
sleep 5
curl http://apigateway:3000/deposits | jq
