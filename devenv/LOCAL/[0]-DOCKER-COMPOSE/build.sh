#!/usr/bin/env bash
CWD=$(pwd)
docker compose -f $CWD/docker-compose.yml build
