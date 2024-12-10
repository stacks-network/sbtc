# sBTC signers: `mainnet` Docker Compose

This `README` details how to set up a sBTC signer through Docker Compose for a
`mainnet` deployment.

## Requirements

[This documentation page](https://docs.stacks.co/guides-and-tutorials/sbtc/how-to-run-sbtc-signer)
details how to setup Bitcoin and Stacks full nodes.

### Chainstate archives

In case you need to quickly sync a Bitcoin or Stacks full-node, here are two
archives you can use.

Warning: restoring from the archive will require 2x disk space (to download the
archive first and then unzip its contents).

| Network | Archive                                                                                              |
| ------- | ---------------------------------------------------------------------------------------------------- |
| Bitcoin | [archive](https://bitcoin-chainstate-prod.s3.us-east-1.amazonaws.com/data.tar.gz)                    |
| Stacks  | [archive](https://archive.hiro.so/mainnet/stacks-blockchain/mainnet-stacks-blockchain-latest.tar.gz) |

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
page](https://github.com/stacks-network/docs/blob/feat/sbtc_signer_best_practices/guides-and-tutorials/sbtc/best_practices_for_running_an_sbtc_signer.md)
for best practices.
