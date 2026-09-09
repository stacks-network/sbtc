# sBTC address constructor

A static, client-side website for independently computing sBTC deposit addresses. It can read a Stacks recipient and the public key for a P2WPKH Bitcoin address from a wallet through Stacks Connect, or accept all inputs manually.

The site does not construct, sign, or broadcast transactions. Users should make deposits through the [official sBTC Bridge](https://sbtc.stacks.co/).

## Development

From the repository root:

```bash
pnpm install
pnpm --filter @stacks-sbtc/deposit-address-verifier dev
```

Run the checks and create the static build with:

```bash
pnpm --filter @stacks-sbtc/deposit-address-verifier test
pnpm --filter @stacks-sbtc/deposit-address-verifier lint
pnpm --filter @stacks-sbtc/deposit-address-verifier build
```

The production files are written to `web/deposit-address-verifier/dist`.

## Deployment

The `Deploy sBTC address constructor` workflow publishes the static build to GitHub Pages after it has been manually triggered.
