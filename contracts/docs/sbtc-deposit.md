# sbtc-deposit

[`sbtc-deposit.clar`](../contracts/sbtc-deposit.clar)

sBTC Deposit contract

**Public functions:**

- [`complete-deposit-wrapper`](#complete-deposit-wrapper)

**Read-only functions:**

**Private functions:**

**Maps**

**Variables**

**Constants**

- [`txid-length`](#txid-length)
- [`ERR_TXID_LEN`](#err_txid_len)
- [`ERR_DEPOSIT_REPLAY`](#err_deposit_replay)

## Functions

### complete-deposit-wrapper

[View in file](../contracts/sbtc-deposit.clar#L22)

`(define-public (complete-deposit-wrapper ((txid (buff 32)) (vout-index uint) (amount uint) (recipient principal)) (response (response bool uint) uint))`

public functions
Accept a new deposit request
Note that this function can only be called by the current
bootstrap signer set address - it cannot be called by users directly.
This function handles the validation & minting of sBTC, it then calls
into the sbtc-registry contract to update the state of the protocol

<details>
  <summary>Source code:</summary>

```clarity
(define-public (complete-deposit-wrapper (txid (buff 32)) (vout-index uint) (amount uint) (recipient principal))
    (let
        (
            (replay-fetch (contract-call? .sbtc-registry get-completed-deposit txid vout-index))
        )

        ;; TODO
        ;; Check that tx-sender is the bootstrap signer

        ;; Check that txid is the correct length
        (asserts! (is-eq (len txid) txid-length) ERR_TXID_LEN)

        ;; Assert that the deposit has not already been completed (no replay)
        (asserts! (is-none replay-fetch) ERR_DEPOSIT_REPLAY)

        ;; TODO
        ;; Mint the sBTC to the recipient

        ;; Complete the deposit
        (ok (contract-call? .sbtc-registry complete-deposit txid vout-index amount recipient))
    )
)
```

</details>

**Parameters:**

| Name       | Type      |
| ---------- | --------- |
| txid       | (buff 32) |
| vout-index | uint      |
| amount     | uint      |
| recipient  | principal |

## Maps

## Variables

## Constants

### txid-length

constants

```clarity
(define-constant txid-length u32)
```

[View in file](../contracts/sbtc-deposit.clar#L4)

### ERR_TXID_LEN

error codes

```clarity
(define-constant ERR_TXID_LEN (err u300))
```

[View in file](../contracts/sbtc-deposit.clar#L7)

### ERR_DEPOSIT_REPLAY

```clarity
(define-constant ERR_DEPOSIT_REPLAY (err u301))
```

[View in file](../contracts/sbtc-deposit.clar#L8)
