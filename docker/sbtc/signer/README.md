# sBTC Signer Configuration

The sBTC signer configuration is contained within this directory as `signer-config.toml`.

In `../docker-compose.yml`, the services `sbtc-signer-1`, `sbtc-signer-2` and
`sbtc-signer-3` load this config as a base and override instance-specific values
using environment variables.

## sBTC Accounts

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
‣ Mnemonic:     puppy ladder save liar close fix deliver later victory ugly rural artwork topic
                camera orphan depart power pottery retreat walk ignore army
                employ turkey
‣ Private Key:  9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee01
‣ Public Key:   031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380
‣ STX Address:  ST2XAK68AR2TKBQBFNYSK9KN2AY9CVA91A7CSK63Z
‣ BTC Address:  mxXw9bceXuFB6HZjqriS527kTqt5H9VczT
‣ WIF:          cSowFfhhyLhwsxCQHYzFGLKZYGjob3oQ6ZwH1v4WAAcxeb4Wn4ro
```

### Signer 3 Account

The account which `sbtc-signer-3` uses is as follows. This is also used by the
`stacks-signer-3` and is configured in the `stacker` and `monitor` services.

```text
‣ Mnemonic:     want stove parent truly label duck small aspect pumpkin image purity stove
                pottery check voyage person weasel category cat inspire portion
                sun lab piece
‣ Private Key:  3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb7401
‣ Public Key:   02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c
‣ STX Address:  ST1J9R0VMA5GQTW65QVHW1KVSKD7MCGT27X37A551
‣ BTC Address:  mpgvmF9DSDBrbxUY4rbsPmWkYakoDXr19j
‣ WIF:          cPggi5foghgcKAGnbRwCLMDpQCCmWVUZ9r7PkWQ7cCfK69BWLXdk
```

## Transaction-Generation Accounts

### Account 1

```text
‣ Mnemonic:     sorry door captain volume century wood soap asset scheme idea alley mammal
                effort shoulder gravity car pistol reform aisle gadget gown
                future lawsuit tone
‣ Private Key:  e26e611fc92fe535c5e2e58a6a446375bb5e3b471440af21bbe327384befb50a01
‣ Public Key:   03fb84a4a2931e7d0ec36bf6e695233bec878fd545bad580751cf4a49d78a7bb27
‣ STX Address:  ST1YEHRRYJ4GF9CYBFFN0ZVCXX1APSBEEQ5KEDN7M
‣ BTC Address:  mruR58H7NvUgmDydv1BM8zMT8og6QxN1Rx
‣ WIF:          cVArVw9FJPeygtZhRtHJEhDqEQTeC3Ybw3UjXt1ir6RgMkMj1Mcz
```

### Account 2

```text
‣ Mnemonic:     album bid grant because narrow unusual unknown machine quick core dolphin occur
                repair decade toilet betray word people mule assume gesture
                faint trend about
‣ Private Key:  e3ebd73a51da9a2ab0c6679145420876bf4338554a8972e3ab200cef7adbec6001
‣ Public Key:   03e5049566e351debe8c4d9918faafac751fdcc0e80d3db59069b45761b39015f5
‣ STX Address:  ST1WNJTS9JM1JYGK758B10DBAMBZ0K23ADP392SBV
‣ BTC Address:  mrabBBLKnSZq8fziECh4TsNwVbmdGv6JDV
‣ WIF:          cVDkVrPTBEVa9fFGwFQT4zKi9dXFUJqLym3Ct6MJTepT6Wh5413g
```

### Account 3

```text
‣ Mnemonic:     action still web blush proud cat axis barrel tower assault cram catch more soup
                auction require again valley letter calm license release fruit
                industry
‣ Private Key:  0bfff38daea4561a4343c9b3f29bfb06e32a988868fc68beed31a6c0f6de4cf701
‣ Public Key:   03a89261c20768ce41930371cd4c0d756c872e96b8ff749ac044199cc7100ccd71
‣ STX Address:  ST1MDWBDVDGAANEH9001HGXQA6XRNK7PX7A7X8M6R
‣ BTC Address:  mq5SjFHAPh93ZnFLc6Jev8yqn2iLg28Q5B
‣ WIF:          cMz2ZSsaVgWPFUkE44zHpJepB4NdwB9L938h53hQfFoot81AZFb3
```
