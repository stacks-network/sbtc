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

> **NOTE:** You will **need** to run a regtest node in order to run an sBTC signer.
> This differs from what the stacks testnet signer needs because there's a port
> that the regtest node needs to expose to the sbtc signer that isn't exposed on
> the public Bitcoin regtest node hosted by Hiro, and isn't required by the stacks signer.

sBTC signers require both a Bitcoin node and a Stacks node. You can find example configs at
the links in the table below, but **you will need to customize the configurations based on your specific deployment.**

If you already have a stacks node with a signer running, that's great! You'll just need
to tweak the config file a little.

| Network         | Archive                                                                                              | Example Config                           |
| --------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Bitcoin regtest | [archive](https://drive.google.com/drive/u/3/folders/1KvpmIxvX8Rh7H8Th91qbc_HsbhQLi13V)              | [example config](./bitcoin/bitcoin.conf) |
| Stacks testnet  | [archive](https://archive.hiro.so/testnet/stacks-blockchain/testnet-stacks-blockchain-latest.tar.gz) | [example config](./stacks/Config.toml)   |

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

We will provide a postgres file for you to download that needs to be extracted
into the `./postgres/data` directory. To do this with a single command you
can run the following in the directory that you'll run the docker compose
from.

```bash
mkdir -p ./postgres/data \
  && tar -xvf <your-postgres-file> \
  -C ./postgres
```

You should now have `./postgres/data` populated with the data we provided.
Note that there was one instance where the data had permission that didn't
work for the folks running the signer. If your signer is saying that it
cannot find the signer database either:

1. The database is not in the location `.postgres/data`
2. It has incompatable permissions with the docker container runner.

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

If you have an existing event observer, you can add this directly below that
configuration, like so:

```toml
[[events_observer]]
endpoint = "<some-other-host>:1234"
events_keys = [
    "some-other-event-key",
]

[[events_observer]]
endpoint = "<your_signer_hostname>:8801"
events_keys = [
    "SNGWPN3XDAQE673MXYXF81016M50NHF5X5PWWM70.sbtc-registry::print",
]
```

## Environment Configuration

We will provide you with a starter `.env` file that has the following fields:

```
STREAM_NAME=<provided_stream_name>
SIGNER_SIGNER__PRIVATE_KEY=<provided_private_key>
EMILY_API_KEY=<provided_emily_api_key>
AWS_ACCESS_KEY_ID=<provided_access_key_id>
AWS_SECRET_ACCESS_KEY=<provided_secret_access_key>
```

### Configure ZMQ endpoints for your Bitcoin node

If you have used the [configuration](./bitcoin/bitcoin.conf) from this
repository, you are all set.

```conf
zmqpubhashblock=tcp://*:28332
zmqpubrawblock=tcp://*:28332
```

### Configure the blocklist client

> **NOTE:** You will need to send a request to chainanalysis to get an API key, which
> is as simple as providing your contact info and waiting for an email with the key.
> The request link is right below.

Add the API key obtained
[here](https://go.chainalysis.com/crypto-sanctions-screening.html) to the following to the
`.env` file we provided.

```bash
BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=<API_KEY>
```

## Running

Run `docker-compose -f ./docker-compose.testnet.yml up`.
