To run signers locally:

```bash
# from devenv/local/docker-compose
docker compose --profile bitcoin-mempool up -d

# from sbtc root
(source devenv/local/envs/signer-1.env && cargo run --bin sbtc-signer -- --config devenv/local/docker-compose/sbtc-signer/signer-config.toml --migrate-db)
(source devenv/local/envs/signer-2.env && cargo run --bin sbtc-signer -- --config devenv/local/docker-compose/sbtc-signer/signer-config.toml --migrate-db)
(source devenv/local/envs/signer-3.env && cargo run --bin sbtc-signer -- --config devenv/local/docker-compose/sbtc-signer/signer-config.toml --migrate-db)
```
