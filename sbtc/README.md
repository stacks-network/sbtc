# lib-sbtc

A library for creating Bitcoin deposit transactions that can be handled by the sBTC signers.

## CLI

The `sbtc` binary provides utilities for working with sBTC Bitcoin addresses. It
can independently construct deposit addresses and retrieve the current signers'
Bitcoin address from the sBTC registry.

Build the CLI with the `cli` feature enabled from the root of this repository:

```console
$ cargo build --release -p sbtc --features cli
```

Display the available commands or detailed help for either command with:

```console
$ ./target/release/sbtc --help
$ ./target/release/sbtc compute-deposit-address --help
$ ./target/release/sbtc signers-address --help
```

### Signers address

Return the current sBTC signers' Bitcoin address with:

```console
$ ./target/release/sbtc signers-address
```

This fetches the current aggregate public key from the sBTC registry and derives the signers' key-path Taproot address. Use `--network` to select the Bitcoin network, `--stacks-api-url` to query a different Stacks API endpoint, and `--deployer` to select a different sBTC registry deployer.

### Deposit address construction

The official Stacks guide to [pegging BTC into sBTC](https://docs.stacks.co/more-guides/sbtc/bridging-bitcoin/btc-to-sbtc) is another source for constructing sBTC deposit addresses and integrating the complete deposit flow.

Constructing an address is useful for independent verification. Before sending Bitcoin to a computed address, users are strongly encouraged to use the [bridge](https://sbtc.stacks.co), which registers the deposit with Emily as required to complete the deposit and obtain sBTC.

Run the command from the repository root with:

```console
$ ./target/release/sbtc compute-deposit-address <STACKS_RECIPIENT> \
  --reclaim-pubkey <PUBLIC_KEY>
```

For example, the following uses the sBTC mainnet deployer as the recipient and a well-known test public key as the reclaim key:

```console
$ ./target/release/sbtc compute-deposit-address \
  SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4 \
  --reclaim-pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

> [!WARNING]
> The example reclaim key above corresponds to the publicly known private key `1`. Never send real Bitcoin to the resulting address. Use a reclaim public key controlled by the depositor in production.

By default, the binary fetches the signers' current aggregate public key from the mainnet sBTC registry smart contract through the Hiro API.

You can find the key yourself on the [sBTC bootstrap-signers transactions](https://explorer.hiro.so/txid/SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-bootstrap-signers?chain=mainnet&tab=transactions) page in the Stacks Explorer. Open the most recent successful, confirmed `rotate-keys-wrapper` transaction and find `new-aggregate-pubkey` under **Function called**. This is a 33-byte compressed key.

Pass the copied value directly with `--signers-aggregate-pubkey`; the CLI accepts the Explorer's `0x` prefix and converts the compressed key to x-only form. For example, replace the aggregate key below with the value from the latest confirmed key rotation to construct a deposit address:

```console
$ ./target/release/sbtc compute-deposit-address \
  SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4 \
  --reclaim-pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  --signers-aggregate-pubkey 0x033920f589c2b367400732d2dd61d11b300ad95b2b1bbf008eabcf8cddfee0c12c
```

> [!WARNING]
> This example reuses the unsafe test reclaim key whose private key is publicly known. Never send real Bitcoin to the resulting address.

When `--signers-aggregate-pubkey` is set, the command uses that value directly and makes no network requests.

The reclaim public key may be either a 32-byte x-only key or a 33-byte compressed key, encoded as hex. The CLI converts a compressed key to its x-only form automatically.

When `--reclaim-pubkey` is used, the CLI constructs the complete reclaim script as `<lock-time> OP_CSV OP_DROP <x-only-public-key> OP_CHECKSIG`. `OP_CSV` leaves the lock time on the stack, so the generated `OP_DROP` removes it before signature verification.

For a custom reclaim condition, pass the complete hex-encoded reclaim script, including its lock-time prefix. This is an advanced option: the CLI validates that it conforms to the sbtc protocol, but it does not determine whether the script is spendable. It does not insert `OP_DROP` or otherwise modify the script's semantics. Note that `--lock-time` and `--reclaim-pubkey` cannot be used with `--reclaim-script`.

```console
$ ./target/release/sbtc compute-deposit-address <STACKS_RECIPIENT> \
  --reclaim-script <SCRIPT_HEX>
```

The default maximum L1 sweep fee is 80,000 satoshis and the default relative reclaim lock time is 950 Bitcoin blocks, matching the values used on the sBTC bridge at [sbtc.stacks.co](https://sbtc.stacks.co). Use `--help` to see overrides for these values, the signers' aggregate public key, the Stacks API, the registry deployer, and the Bitcoin network.
