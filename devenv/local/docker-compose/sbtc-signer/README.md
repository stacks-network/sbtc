# sTBTC Signer Configuration

The sBTC signer configuration is contained within this directory as `signer-config.toml`.

In `../docker-compose.yml`, the services `sbtc-signer-1`, `sbtc-signer-2` and
`sbtc-signer-3` load this config as a base and override instance-specific values
using environment variables.

## Accounts

### Deployer Account

If manually deploying contracts, use this account as it's what's configured in the
sBTC signer config.

```text
‣ Mnemonic:     keep can record bracket note hip face pudding castle detail few sunset review
                burger enhance foil lamp estate reopen butter then wasp pen kick
‣ Private Key:  27e27a9c242bcf79784bb8b19c8d875e23aaf65c132d54a47c84e1a5a67bc62601
‣ Public Key:   025fa7693cfe4b7c7beccdd9e4bfe77f77a3779d5a58faeb69ead7d1ba94d64f76
‣ STX Address:  ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039
‣ BTC Address:  mwp5EpXXVsZxzQRC7yrDe1CJBsyub9f91n
‣ WIF:          cNvERZ1Ci4NQydr5dTuW8K2JuoyfjLJgYVskrLzBoXREnRVbS9qx
```

### Signer 1 Account

The account which `sbtc-signer-1` uses is as follows. This is also used by the
`stacks-signer-1` and is configured in the `stacker` and `monitor` services.

```text
‣ Mnemonic:     number pause unfold flash cover thank spray road moment scatter wreck scrap
                cricket enemy enlist chest all dog force magnet giggle canyon
                spatial such
‣ Private Key:  41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc01
‣ Public Key:   035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46
‣ STX Address:  ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H
‣ BTC Address:  mt56SJB4aQRz8xA13gnkNnqxZc2dESq6Sq
‣ WIF:          cPmokz1FLbW5KyZGMeSoDBeoRB51358dPzRJatiazpjLUnfaDe55
```

### Signer 2 Account

The account which `sbtc-signer-2` uses is as follows. This is also used by the
`stacks-signer-2` and is configured in the `stacker` and `monitor` services.

```text
# ‣ Mnemonic:     puppy ladder save liar close fix deliver later victory ugly rural artwork topic
#                 camera orphan depart power pottery retreat walk ignore army
#                 employ turkey
# ‣ Private Key:  9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee01
# ‣ Public Key:   031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380
# ‣ STX Address:  ST2XAK68AR2TKBQBFNYSK9KN2AY9CVA91A7CSK63Z
# ‣ BTC Address:  mxXw9bceXuFB6HZjqriS527kTqt5H9VczT
# ‣ WIF:          cSowFfhhyLhwsxCQHYzFGLKZYGjob3oQ6ZwH1v4WAAcxeb4Wn4ro
```

### Signer 3 Account

The account which `sbtc-signer-3` uses is as follows. This is also used by the
`stacks-signer-3` and is configured in the `stacker` and `monitor` services.

```text
# ‣ Mnemonic:     want stove parent truly label duck small aspect pumpkin image purity stove
#                 pottery check voyage person weasel category cat inspire portion
#                 sun lab piece
# ‣ Private Key:  3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb7401
# ‣ Public Key:   02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c
# ‣ STX Address:  ST1J9R0VMA5GQTW65QVHW1KVSKD7MCGT27X37A551
# ‣ BTC Address:  mpgvmF9DSDBrbxUY4rbsPmWkYakoDXr19j
# ‣ WIF:          cPggi5foghgcKAGnbRwCLMDpQCCmWVUZ9r7PkWQ7cCfK69BWLXdk
```
