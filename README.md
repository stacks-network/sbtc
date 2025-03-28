# sBTC

[![License: GPL v3][gpl-v3-badge]][gpl-v3-link]

### Links

- [sBTC Landing Page](https://sbtc.tech/)
- [sBTC Docs](https://docs.stacks.co/concepts/sbtc)

## Releases

See [`RELEASE.md`](./RELEASE.md).

## Design Docs

**All decisions are made and tracked via GitHub issues where they and their rationale can be verified publicly.** Due to sBTC's critical nature extensive research and planning has been done to ensure all funds remain secure on launch.

- [Research GitHub Issues](https://github.com/stacks-network/sbtc/issues?q=is%3Aissue+label%3Aresearch+)
- [Design GitHub Issues](https://github.com/stacks-network/sbtc/issues?q=is%3Aissue+label%3Adesign+)
- [Additional Docs and Material](https://drive.google.com/drive/folders/1CgsrR1Q5y7a7u7HyOtdM_zOFxSXm518J)

## Contributing

**Before going any further please review our [code of conduct](CODE_OF_CONDUCT.md)**

### Tools to Install

> This repository is under development and this section may become outdated. Please
> open a GitHub issue if you believe some tools are missing.

The following are the developer tools that you should install on your local machine in order to build and run the sources in this repository.

- **[Cargo](https://doc.rust-lang.org/cargo/)** - [Installation Guide](https://doc.rust-lang.org/cargo/getting-started/installation.html) - Builds rust packages.
- **[Cargo-lambda](https://www.cargo-lambda.info/)** - [Installation Guide](https://www.cargo-lambda.info/guide/getting-started.html) - Compile the package for AWS Lambda.
- **[pnpm](https://pnpm.io)** - [Installation guide](https://pnpm.io/installation) - Manages node packages
- **[Make](https://www.gnu.org/software/make/)** - Development task runner; natively present on nearly every system.
- **[Docker](https://docs.docker.com/manuals/)** - [Installation Guide](https://docs.docker.com/desktop/). This is used for running integration tests.
- **[protoc](https://github.com/protocolbuffers/protobuf)** - [Installation Guide](https://grpc.io/docs/protoc-installation/). Compiles protobuf files.

#### Developer shell through `nix`

If you have `nix` and `flakes` installed (e.g. through the [DeterminateSystems
installer](https://github.com/DeterminateSystems/nix-installer)), running the
following command will enter a shell with all dependencies installed:

```bash
$ nix develop
```

#### Tool Versions

This command should check the version of the dependencies required for the sBTC
resources to be built and tested.

```bash
echo "\n--- sBTC tool versions ---" \
    && cargo --version \
    && cargo lambda --version \
    && echo "pnpm $(pnpm --version)" \
    && make --version | head -n 1
```

Below is the output on a machine that is able to build and run all the sources and tests.

```
--- sBTC tool versions ---
cargo 1.85.1 (d73d2caf9 2024-12-31)
cargo-lambda 1.2.1 (12f9b61 2024-04-05Z)
pnpm 9.1.0
GNU Make 3.81
```

### Building

To build the sources we recommend you use the `Makefile` commands; they'll build the dependencies in the right order.

- `make install` - Installs node dependencies
- `make build` - Builds packages
- `make lint` - Lints packages
- `make clean` - Cleans workspace
- `make test` - Run non-integration tests
- `make integration-test` - Run integration tests.
    - Before running integration tests you must run `make integration-env-up`
    - After running integration tests you must run `make integration-env-down`

For other commands read the `Makefile` at repository root.

### Local devenv

A local development network is managed through a Docker Compose file in [`./docker/docker-compose.yml`](./docker/docker-compose.yml). `make` commands for starting and stopping it are:

- `make devenv-up`: Start the network
- `make devenv-down`: Stop the network and remove containers and networks

Once running, the following services are available:

- Stacks node at [localhost:20443](http://localhost:20443)
- Stacks API at [localhost:3999](http://localhost:3999)
- Bitcoin node at [devnet:devnet@localhost:18443](http://devnet:devnet@localhost:18443)
- 3 Nakamoto signers at [localhost:30000](http://localhost:30000), [localhost:30001](http://localhost:30001), and [localhost:30002](http://localhost:30002)
- Stacks explorer at [localhost:3020](http://localhost:3020)
- Mempool.space Bitcoin explorer at [localhost:8083](http://localhost:8083)

#### Update local docker builds

To rebuild the containers from your current branch you can use:
```bash
# Build signers + emily (~2m, if `sbtc-build` was already built)
docker compose -f docker/docker-compose.yml --profile default --profile bitcoin-mempool --profile sbtc-signer build
# Build bridge-website (~2m)
docker compose -f docker/docker-compose.yml build --no-cache sbtc-bridge-website
```

Note: you may need to disable buildkit (prefixing the commands above with `DOCKER_BUILDKIT=0`) if you get `pull access denied` when building the containers on MacOS.

#### Play with devenv

To interact with the local devenv, ensure you have built latest version (see above) and run devenv with `make devenv-up`.

Then, wait for everything to be ready:
 - Wait for Nakamoto: check the stacks explorer and wait for Nakamoto (usually around block #30). Explorer links:
   - Stacks: http://localhost:3020/?chain=testnet&api=http://localhost:3999
   - Bitcoin: http://localhost:8083/
 - Wait for sBTC signers bootstrap: on stacks explorer, check the deployer account (`SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS`) for contract deployment and the first rotate key transaction.

Once you see the rotate key transaction, everything is ready! Now you can create a deposit request in two ways.

To programmatically fund the signers aggregate key and create a new deposit request, you can run:
```bash
./signers.sh demo
```

To use the bridge webapp, you can go to (http://localhost:3010). You will need to get signers info using `./signers.sh info`, then ensure that on the settings tab you have the correct settings:
 - bitcoin: http://bitcoin:18443/
 - emily: http://emily-server:3031
 - signers pubkey: the pubkey from the command above.

Now go to transfer and fund (eg, sending `1` btc) the signers aggregate key bitcoin address (from the command above). You can use the transfer tab to fund the wallet you want to use for the deposits as well.

Finally, go to the deposit tab and issue a new deposit.

Once you submitted a deposit request (either ways), you can follow it:
 - First, on the bitcoin explorer, you can see the deposit tx, and a block later the sweep tx from the signers consuming its output
 - Then, on the stacks explorer, you can see the `complete-deposit` contract call (to `SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS`), minting the net sBTC to the recipient account.

### Cargo Vet CI

This GitHub Actions workflow, Cargo Vet, is designed to automate the vetting of the project dependencies, ensuring they meet security and compliance standards. It runs on every push to the repository and provides detailed feedback if unvetted dependencies are detected.

#### How to Use This Workflow

- **Automatic Trigger**: The workflow runs automatically on every push to the repository. You don't need to manually trigger it unless you want to test it specifically.

- **Reviewing Results**: Success: If all dependencies are vetted, the workflow completes successfully, and no further action is required.

- **Failure**: Check the GitHub Actions logs for errors and annotations about unvetted dependencies.
Download the audit-suggestions.txt artifact from the "Artifacts" section of the GitHub Actions interface for a detailed report.

- **Addressing Unvetted Dependencies**: Use the suggestions in the audit-suggestions.txt file to update your dependency audit policies in the supply-chain.toml file.

Running this command you are able to check the suggestions offline:

```bash
cargo vet suggest > audit-suggestions.txt
```

Review the suggestions in audit-suggestions.txt and manually update your supply-chain.toml file to approve or reject dependencies based on your audit.


### Git hooks

[`./devenv/hooks`](./devenv/hooks) contains Git hooks you can install to run
`pre-commit` checks. You can (optionally) run `make install-git-hooks` to
install them. Be advised: under the hood, the hooks will run `make lint`, which
relies on `clippy` and `rust fmt` and might need to download and compile
dependencies.

### Operating Systems

This project currently supports development on UNIX-based operating systems but
does not support development on Windows or z/OS.

## Security

See [this](./SECURITY.md).

[gpl-v3-badge]: https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat
[gpl-v3-link]: https://www.gnu.org/licenses/gpl-3.0
