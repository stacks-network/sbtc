#!/usr/bin/env bash

if [ $? -eq 0 ]; then
    docker compose up -d --build
else
    echo "Build failed, not starting devenv"
fi
