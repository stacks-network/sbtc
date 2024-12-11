# sBTC signers: `mainnet` Docker Compose

This `README` details how to set up a sBTC signer through Docker Compose for a
`mainnet` deployment.

## Requirements

[This documentation page](https://docs.stacks.co/guides-and-tutorials/sbtc/how-to-run-sbtc-signer)
details how to setup Bitcoin and Stacks full nodes.

The [`./nodes` folder](./nodes/) contains a Docker Compose override which shows
how to run the Bitcoin and Stacks full nodes.

### Chainstate archives

In case you need to quickly sync a Bitcoin or Stacks full-node, here are two
archives you can use.

Warning: restoring from the archive will require 2x disk space (to download the
archive first and then unzip its contents).

| Network | Archive                                                                                              |
| ------- | ---------------------------------------------------------------------------------------------------- |
| Bitcoin | [archive](https://bitcoin-chainstate-prod.s3.us-east-1.amazonaws.com/data.tar.gz)                    |
| Stacks  | [archive](https://archive.hiro.so/mainnet/stacks-blockchain/mainnet-stacks-blockchain-latest.tar.gz) |

Extract to `/mnt/bitcoin` and `/mnt/stacks` if using the provided Docker Compose
configuration for the nodes as well.

## Configuration

All configuration is handled through environmental variables, which are parsed
at the beginning of the provided `docker-compose.yml` file:

```bash
$ cat docker-compose.yml | grep Required | cut -d " " -f 5

${POSTGRES_PASSWORD}
${BITCOIN_RPC_USERNAME}
${BITCOIN_RPC_PASSWORD}
${BITCOIN_RPC_HOST}
${STACKS_RPC_HOST}
${SIGNER_SIGNER__PRIVATE_KEY}
${EMILY_API_KEY}
${BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY}
${STREAM_NAME}
${AWS_ACCESS_KEY_ID}
${AWS_SECRET_ACCESS_KEY}
```

`docker-compose` will pick them up from a `.env` file in the same folder as the `docker-compose.yml` file.
You can create the `.env` structure as follows:

```bash
cat docker-compose.yml | grep Required | cut -d " " -f 5 | sed -E 's/\$\{([^}]+)\}/\1=/g' | tee .env

POSTGRES_PASSWORD=
BITCOIN_RPC_USERNAME=
BITCOIN_RPC_PASSWORD=
BITCOIN_RPC_HOST=
STACKS_RPC_HOST=
SIGNER_SIGNER__PRIVATE_KEY=
EMILY_API_KEY=
BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=
STREAM_NAME=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
```

## Best practices

Please refer to [this documentation
page](https://docs.stacks.co/guides-and-tutorials/sbtc/best-practices-for-running-an-sbtc-signer)
for best practices.

## Run the stack

You will need a recent-enough version of Docker and Docker Compose. The
following have been confirmed to work:

```bash
$ docker --version
Docker version 27.4.0, build bde2b89

$ docker compose version
Docker Compose version v2.31.0
```

After creating the `.env` that includes the configuration, you can use the
following to spin up the stack.

```bash
sudo docker compose --env-file .env up
```

### Run the Stacks and Bitcoin nodes too

Alternatively, you can run the full stack (including Bitcoin and Stacks nodes)
as follows:

```bash
sudo docker compose --env-file .env -f docker-compose.yml -f nodes/docker-compose.chains.yml up
```

This requires the chain-state for Bitcoin and Stacks to be present,
respectively, at `/mnt/bitcoin` and `/mnt/stacks`.
