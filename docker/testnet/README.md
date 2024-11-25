# `testnet` setup

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

Copy the provided `data` folder within the `./postgres` directory.

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

Add the following to a `.env` file in this directory:

```bash
STREAM_NAME=<provided_stream_name>
AWS_ACCESS_KEY_ID=<provided_access_key_id>
AWS_SECRET_ACCESS_KEY=<provided_secret_access_key>
```

### Configure the blocklist client

Add the API key obtained
[here](https://go.chainalysis.com/crypto-sanctions-screening.html) to a `.env`
file in this directory:

```bash
BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=<API_KEY>
```

## Running

Run `docker-compose -f ./docker-compose.testnet.yml up`.
