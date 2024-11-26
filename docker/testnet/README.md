# `testnet` setup

This `README` details how to set up a sBTC signer for a testnet deployment.

In a production deployment, signers would perform a key ceremony to bootstrap
the system: each would generate a private key and distribute the corresponding
public key to the others.

In testnet, instead, the signer bootstrap set has been pre-determined. This
allows to gradually decommission the "development" signer instances used to
bootstrap the testnet and onboard external signers without having to re-run
distributed key generation (DKG).

## Requirements

sBTC signers require both a Bitcoin node and a Stacks node. This repository
includes examples of:

- A [Bitcoin regtest config](./bitcoin/bitcoin.conf) and
- A [Stacks primary testnet configuration](./stacks/Config.toml).

You will need to customize the configuration based on your specific deployment.

Syncing a Bitcoin regtest node at the time of writing takes roughly 5 hours. If
helpful, we can provide an archive of the chain-state to speed things up.

You can also bootstrap the Stacks testnet node through an
[archive](https://docs.stacks.co/guides-and-tutorials/running-a-signer#start-with-an-archive).

## Configuration

Clone this repository and `cd` to this directory.

### Configure the Signer

- Copy `./config/signer-config.toml.sample` to `./config/signer-config.toml`.
- Edit `./config/signer-config.toml` to add:
  - The provided Emily API key.
  - The host/port of your Bitcoin node RPC endpoint.
  - The host/port of your Bitcoin zmqpubhash endpoint.
  - The host/port of your Stacks RPC endpoint.
  - The provided signer private key.
  - The URI to a Postgresql DB.

### Configure the Postgresql database

Copy the provided `data` folder to the `./postgres` directory.

### Add an event-listener to your Stacks node

Note that the following Stacks address MUST be the one specified in the
`deployer` key config of the Signer configuration.

```toml
[[events_observer]]
endpoint = "<your_signer_hostname>:8801"
events_keys = [
    "SNGWPN3XDAQE673MXYXF81016M50NHF5X5PWWM70.sbtc-registry::print",
]
```

### Configure logging

Add the following to the `.env` file in this directory:

```bash
STREAM_NAME=<provided_stream_name>
AWS_ACCESS_KEY_ID=<provided_access_key_id>
AWS_SECRET_ACCESS_KEY=<provided_secret_access_key>
```

### Configure the blocklist client

Add the API key obtained
[here](https://go.chainalysis.com/crypto-sanctions-screening.html) to the `.env`
file in this directory:

```bash
BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=<API_KEY>
```

## Running

Run `docker-compose -f ./docker-compose.testnet.yml up`.
