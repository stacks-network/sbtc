#!/usr/bin/env bash
# CWD=$(dirname "$0")
CWD=$(pwd)
docker compose -f $CWD/docker-compose.yml build
