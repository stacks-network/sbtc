#!/bin/bash

sleep 5
curl http://apigateway:3000/deposits | jq
