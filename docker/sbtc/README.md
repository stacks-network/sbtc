# /docker/sbtc/emily

This folder contains three different docker definitions.
1. aws-setup - sets up the AWS resources necessary for the Emily API to function
2. handler-lambda - Runs the Emily handler as a serverless lambda
3. handler-server - Runs the Emily handler as a server, better for local testing and can compile for ARM 64 systems unlike the `handler-lambda`

This environment can be run with the local `docker-compose.yml` but will not
have any of the rest of the resources for the whole sBTC system.
