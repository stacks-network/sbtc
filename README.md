# sBTC

> Note: This repo is still in early development and is not ready for production use.

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

> This section is under development and may be missing some tools. Please
> open a GitHub issue if you believe some tools are missing.

The following are the developer tools that you should install on your local machine in
order to build and run the sources in this repository.

- **[Cargo](https://doc.rust-lang.org/cargo/)** - [Installation Guide](https://doc.rust-lang.org/cargo/getting-started/installation.html) - Builds rust packages.
- **[npm](https://www.npmjs.com/)** - [Installation Guide](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) - Manages node packages
- **[Smithy](https://smithy.io/2.0/index.html)** - [Installation Guide](https://smithy.io/2.0/guides/smithy-cli/cli_installation.html) - Generates OpenAPI templates
- **[OpenAPI Generator](https://openapi-generator.tech/)** - [Installation Guide](https://openapi-generator.tech/docs/installation/) - Generates API clients
- **[Java 21](https://www.oracle.com/java/)** - [Installation Guide](https://www.oracle.com/java/technologies/downloads/) - Required for OpenAPI Generator
- **[AWS CDK](https://aws.amazon.com/cdk/)** - [Installation Guide](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_install) - Compiles cloud infrastructure templates

#### Tool Versions

This command should check the version of the dependencies required for the sBTC
resources to be built and tested.

```bash
echo "\n--- sBTC tool versions ---" \
    && cargo --version \
    && echo "npm $(npm --version)" \
    && echo "cdk $(cdk --version)" \
    && echo "smithy $(smithy --version)" \
    && echo "openapi-generator $(openapi-generator-cli version)" \
    && java --version
```
Below is the output on a machine that is able to build and run all the sources and tests.
```
--- sBTC tool versions ---
cargo 1.77.2 (e52e36006 2024-03-26)
npm 10.5.0
cdk 2.139.1 (build b88f959)
smithy 1.47.0
openapi-generator 7.5.0
openjdk 21.0.2 2024-01-16
OpenJDK Runtime Environment Homebrew (build 21.0.2)
OpenJDK 64-Bit Server VM Homebrew (build 21.0.2, mixed mode, sharing)
```

### Building

To build the sources you will need to run the following command before compiling the rest
of the sources. This is due to the rust code autogeneration that the emily package
requires.

```
cargo build --package emily
```

After running that command you can build the rest of the sources by running cargo
as usual.

```
cargo build && cargo test
```

### Operating Systems

This project currently supports development on UNIX-based operating systems but
does not support development on Windows or z/OS.

[discord-badge]: https://img.shields.io/static/v1?logo=discord&label=discord&message=Join&color=blue
[discord-link]: https://discord.gg/hHaz2gGX
