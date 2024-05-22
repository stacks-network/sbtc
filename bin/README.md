# sBTC Contracts

> Note: This repo is still in early development and is not ready for production use.

## Purpose

Leverage Clarinet to run a reliable devnet.

- up.sh script to run clarinet and then secondary set of containers
- down.sh removes containers
- build.sh - the build script is required for electrs service.
- open.sh - open the relevant services in default browser

Custom stacks/signer binaries can be included in the core set of containers by building clarinet from source, [see](https://github.com/hirosystems/clarinet)

## Dependencies

Depends on Clarinet [>2.6.0] - to install / upgrade use brew on macos

### Recommendations

First run `clarinet devnet start` in the contracts directory - it can take a while to start the stacks api service. Subsequent runs are much quicker to start. The up script assumes the containers have already been initialised.
