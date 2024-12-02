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

> **NOTE:** You will *need* to run a regtest node in order to run an sBTC signer.
> This differs from what the stacks testnet signer needs.

sBTC signers require both a Bitcoin node and a Stacks node. You can find example configs at
the links in the table below, but **you will need to customize the configurations based on your specific deployment.**

| Network | Archive | Example Config |
|-|-|-|
|Bitcoin regtest|[archive](https://drive.google.com/drive/u/3/folders/1KvpmIxvX8Rh7H8Th91qbc_HsbhQLi13V)|[example config](./bitcoin/bitcoin.conf)|
|Stacks testnet|[archive](https://docs.stacks.co/guides-and-tutorials/running-a-signer#start-with-an-archive)|[example config](./stacks/Config.toml)|

## Configuration

> **NOTE:** We will provide the following fields once most of your infrastructure is up and running:
> `STREAM_NAME, SIGNER_SIGNER__PRIVATE_KEY, EMILY_API_KEY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY`

Clone this repository and `cd` to this directory.

### Configure the Signer

- Copy `./config/signer-config.toml.sample` to `./config/signer-config.toml`.
- Edit `./config/signer-config.toml` to add:
  - The provided Emily API key.
  - The provided signer private key.
  - The host/port of your Bitcoin node RPC endpoint.
  - The host/port of your Bitcoin zmqpubhash endpoint.
  - The host/port of your Stacks RPC endpoint.
  - The URI to a Postgresql DB.

### Configure the Postgresql database

Extract the provided `postgres.tar.gz` archive into the `./postgres` directory.
You should now have `postgres/data`.

### Add an event-listener to your Stacks node

If you have used the [configuration](./stacks/Config.toml) from this repository,
you are all set.

```toml
[[events_observer]]
endpoint = "<your_signer_hostname>:8801"
events_keys = [
    "SNGWPN3XDAQE673MXYXF81016M50NHF5X5PWWM70.sbtc-registry::print",
]
```

Note that the Stacks address above MUST be the one specified in the `deployer`
key config of the Signer configuration.

### Configure ZMQ endpoints for your Bitcoin node

If you have used the [configuration](./bitcoin/bitcoin.conf) from this
repository, you are all set.

```conf
zmqpubhashblock=tcp://*:28332
zmqpubrawblock=tcp://*:28332
```

### Configure logging

Add the following to the `.env` file in this directory:

```bash
STREAM_NAME=<provided_stream_name>
AWS_ACCESS_KEY_ID=<provided_access_key_id>
AWS_SECRET_ACCESS_KEY=<provided_secret_access_key>
```

### Configure the blocklist client

> **NOTE:** You will need to send a request to chainanalysis to get an API key, which
> is as simple as providing your contact info and waiting for an email with the key.
> The request link is right below.

Add the API key obtained
[here](https://go.chainalysis.com/crypto-sanctions-screening.html) to the `.env`
file in this directory:

```bash
BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=<API_KEY>
```

## Running

Run `docker-compose -f ./docker-compose.testnet.yml up`.
