# sBTC contracts

This folder contains the Clarity contracts and unit tests for
the sBTC protocol.

## Setup

Install dependencies:

```bash
pnpm install
```

## Running tests

```bash
pnpm test
```

To run tests in "watch" mode:

```bash
pnpm vitest
```

## Generating Clarigen types

This project uses Clarigen to automatically generate types
for contracts.

When contracts are updated, run:

```bash
pnpm clarigen
```

You can also run this in watch mode to automatically generate
types when contracts are updated:

```bash
pnpm clarigen --watch
```

## Contract documentation

Clarigen automatically creates Markdown docs for the contracts
in this folder. They're located in the [./docs](./docs) folder.

You can re-generate them with:

```bash
pnpm clarigen docs
```
