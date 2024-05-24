#!/usr/bin/env bash

./build.sh
docker compose -f docker-compose.yml up -d
