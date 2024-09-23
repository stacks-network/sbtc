# sBTC

> Note: This repo is still in early development and is not ready for production use.

[![License: GPL v3][gpl-v3-badge]][gpl-v3-link]
[![Discord][discord-badge]][discord-link]

Ths repository builds off the developer experience within https://github.com/stacks-network/sbtc-developer-release.

### Links

- [sBTC Landing Page](https://sbtc.tech/)
- [sBTC Rollout Plan](https://www.bitcoinwrites.com/p/sbtc-rollout-bootstrapping-programmable-bitcoin)
- [sBTC Developer Release](https://sbtc.tech/developer-release)

## Decisions and Design

**All decisions are made and tracked via GitHub issues where they and their rationale can be verified publicly.** Due to sBTC's critical nature extensive research and planning has been done to ensure all funds remain secure on launch.

- [Research GitHub Issues](https://github.com/stacks-network/sbtc/issues?q=is%3Aissue+label%3Aresearch+)
- [Design GitHub Issues](https://github.com/stacks-network/sbtc/issues?q=is%3Aissue+label%3Adesign+)

## Contributing

**Before going any further please review our [code of conduct](CODE_OF_CONDUCT.md)**

### Tools to Install

> This repository is under development and this section may become outdated. Please
> open a GitHub issue if you believe some tools are missing.

The following are the developer tools that you should install on your local machine in order to build and run the sources in this repository.

- **[Cargo](https://doc.rust-lang.org/cargo/)** - [Installation Guide](https://doc.rust-lang.org/cargo/getting-started/installation.html) - Builds rust packages.
- **[Cargo-lambda](https://www.cargo-lambda.info/)** - [Installation Guide](https://www.cargo-lambda.info/guide/getting-started.html) - Compile the package for AWS Lambda.
- **[pnpm](https://pnpm.io)** - [Installation guide](https://pnpm.io/installation) - Manages node packages
- **[Smithy](https://smithy.io/2.0/index.html)** - [Installation Guide](https://smithy.io/2.0/guides/smithy-cli/cli_installation.html) - Generates OpenAPI templates
- **[Make](https://www.gnu.org/software/make/)** - Development task runner; natively present on nearly every system.
- **[Docker](https://docs.docker.com/manuals/)** - [Installation Guide](https://docs.docker.com/desktop/). This is used for running integration tests.
- **[protoc](https://github.com/protocolbuffers/protobuf)** - [Installation Guide](https://grpc.io/docs/protoc-installation/). Compiles protobuf files.

#### Tool Versions

This command should check the version of the dependencies required for the sBTC
resources to be built and tested.

```bash
echo "\n--- sBTC tool versions ---" \
    && cargo --version \
    && cargo lambda --version \
    && echo "pnpm $(pnpm --version)" \
    && echo "smithy $(smithy --version)" \
    && make --version | head -n 1
```

Below is the output on a machine that is able to build and run all the sources and tests.

```
--- sBTC tool versions ---
cargo 1.77.2 (e52e36006 2024-03-26)
cargo-lambda 1.2.1 (12f9b61 2024-04-05Z)
pnpm 8.15.4
smithy 1.47.0
GNU Make 3.81
```

### Building

To build the sources we recommend you use the `Makefile` commands; they'll build the dependencies in the right order.

- `make install` - Installs node dependencies
- `make build` - Builds packages
- `make lint` - Lints packages
- `make clean` - Cleans workspace
- `make test` - Run non-integration tests
- `make integration-test` - Run integration tests. This needs local services running; use something like `docker compose --file docker-compose.test.yml up --detach` to start the necessary services.

For other commands read the `Makefile` at repository root.

### Local devenv

A local development network is managed through a Docker Compose file in [`./devenv/local/docker-compose`](./devenv/local/docker-compose). `make` commands for starting and stopping it are:

- `make devenv-up`: Start the network
- `make devenv-down`: Stop the network and remove containers and networks

Once running, the following services are available:

- Stacks node at [localhost:20443](http://localhost:20443)
- Stacks API at [localhost:3999](http://localhost:3999)
- Bitcoin node at [devnet:devnet@localhost:18443](http://devnet:devnet@localhost:18443)
- 3 Nakamoto signers at [localhost:30000](http://localhost:30000), [localhost:30001](http://localhost:30001), and [localhost:30002](http://localhost:30002)
- Stacks explorer at [localhost:3020](http://localhost:3020)
- Mempool.space Bitcoin explorer at [localhost:8083](http://localhost:8083)

### Operating Systems

This project currently supports development on UNIX-based operating systems but
does not support development on Windows or z/OS.

[discord-badge]: https://img.shields.io/static/v1?logo=discord&label=discord&message=Join&color=blue
[discord-link]: https://discord.gg/hHaz2gGX
[gpl-v3-badge]: https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat
[gpl-v3-link]: https://www.gnu.org/licenses/gpl-3.0
