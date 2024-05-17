# sbtc-registry

[`sbtc-registry.clar`](../contracts/sbtc-registry.clar)

sBTC Registry contract

**Public functions:**

- [`create-withdrawal-request`](#create-withdrawal-request)
- [`complete-deposit`](#complete-deposit)
- [`rotate-keys`](#rotate-keys)

**Read-only functions:**

- [`get-withdrawal-request`](#get-withdrawal-request)
- [`get-completed-deposit`](#get-completed-deposit)
- [`get-current-signer-data`](#get-current-signer-data)
- [`get-current-aggregate-pubkey`](#get-current-aggregate-pubkey)
- [`get-current-signer-principal`](#get-current-signer-principal)

**Private functions:**

- [`increment-last-withdrawal-request-id`](#increment-last-withdrawal-request-id)
- [`validate-caller`](#validate-caller)

**Maps**

- [`withdrawal-requests`](#withdrawal-requests)
- [`withdrawal-status`](#withdrawal-status)
- [`completed-deposits`](#completed-deposits)
- [`aggregate-pubkeys`](#aggregate-pubkeys)
- [`multi-sig-address`](#multi-sig-address)

**Variables**

- [`last-withdrawal-request-id`](#last-withdrawal-request-id)
- [`current-signer-set`](#current-signer-set)
- [`current-aggregate-pubkey`](#current-aggregate-pubkey)
- [`current-signer-principal`](#current-signer-principal)

**Constants**

- [`ERR_UNAUTHORIZED`](#err_unauthorized)
- [`ERR_INVALID_REQUEST_ID`](#err_invalid_request_id)
- [`ERR_AGG_PUBKEY_REPLAY`](#err_agg_pubkey_replay)
- [`ERR_MULTI_SIG_REPLAY`](#err_multi_sig_replay)

## Functions

### get-withdrawal-request

[View in file](../contracts/sbtc-registry.clar#L63)

`(define-read-only (get-withdrawal-request ((id uint)) (optional (tuple (amount uint) (block-height uint) (max-fee uint) (recipient (tuple (hashbytes (buff 32)) (version (buff 1)))) (sender principal) (status (optional bool)))))`

Read-only functions
Get a withdrawal request by its ID.
This function returns the fields of the withrawal
request, along with its status.

<details>
  <summary>Source code:</summary>

```clarity
(define-read-only (get-withdrawal-request (id uint))
  (match (map-get? withdrawal-requests id)
    request (some (merge request {
      status: (map-get? withdrawal-status id)
    }))
    none
  )
)
```

</details>

**Parameters:**

| Name | Type |
| ---- | ---- |
| id   | uint |

### get-completed-deposit

[View in file](../contracts/sbtc-registry.clar#L74)

`(define-read-only (get-completed-deposit ((txid (buff 32)) (vout-index uint)) (optional (tuple (amount uint) (recipient principal))))`

Get a completed deposit by its transaction ID & vout index.
This function returns the fields of the completed-deposits map.

<details>
  <summary>Source code:</summary>

```clarity
(define-read-only (get-completed-deposit (txid (buff 32)) (vout-index uint))
  (map-get? completed-deposits {txid: txid, vout-index: vout-index})
)
```

</details>

**Parameters:**

| Name       | Type      |
| ---------- | --------- |
| txid       | (buff 32) |
| vout-index | uint      |

### get-current-signer-data

[View in file](../contracts/sbtc-registry.clar#L80)

`(define-read-only (get-current-signer-data () (tuple (current-aggregate-pubkey (buff 32)) (current-signer-principal principal) (current-signer-set (list 15 (buff 32)))))`

Get the current signer set.
This function returns the current signer set as a list of principals.

<details>
  <summary>Source code:</summary>

```clarity
(define-read-only (get-current-signer-data)
  {
    current-signer-set: (var-get current-signer-set),
    current-aggregate-pubkey: (var-get current-aggregate-pubkey),
    current-signer-principal: (var-get current-signer-principal)
  }
)
```

</details>

### get-current-aggregate-pubkey

[View in file](../contracts/sbtc-registry.clar#L90)

`(define-read-only (get-current-aggregate-pubkey () (buff 32))`

Get the current aggregate pubkey.
This function returns the current aggregate pubkey.

<details>
  <summary>Source code:</summary>

```clarity
(define-read-only (get-current-aggregate-pubkey)
  (var-get current-aggregate-pubkey)
)
```

</details>

### get-current-signer-principal

[View in file](../contracts/sbtc-registry.clar#L96)

`(define-read-only (get-current-signer-principal () principal)`

Get the current signer principal.
This function returns the current signer principal.

<details>
  <summary>Source code:</summary>

```clarity
(define-read-only (get-current-signer-principal)
  (var-get current-signer-principal)
)
```

</details>

### create-withdrawal-request

[View in file](../contracts/sbtc-registry.clar#L112)

`(define-public (create-withdrawal-request ((amount uint) (max-fee uint) (sender principal) (recipient (tuple (hashbytes (buff 32)) (version (buff 1)))) (height uint)) (response uint uint))`

Store a new withdrawal request.
Note that this function can only be called by other sBTC
contracts - it cannot be called by users directly.

This function does not handle validation or moving the funds.
Instead, it is purely for the purpose of storing the request.

The function will emit a print event with the topic "withdrawal-request"
and the data of the request.

<details>
  <summary>Source code:</summary>

```clarity
(define-public (create-withdrawal-request
    (amount uint)
    (max-fee uint)
    (sender principal)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (height uint)
  )
  (let
    (
      (id (increment-last-withdrawal-request-id))
    )
    (try! (validate-caller))
    ;; #[allow(unchecked_data)]
    (map-insert withdrawal-requests id {
      amount: amount,
      max-fee: max-fee,
      sender: sender,
      recipient: recipient,
      block-height: height,
    })
    (print {
      topic: "withdrawal-request",
      amount: amount,
      request-id: id,
      sender: sender,
      recipient: recipient,
      block-height: height,
      max-fee: max-fee,
    })
    (ok id)
  )
)
```

</details>

**Parameters:**

| Name      | Type                                             |
| --------- | ------------------------------------------------ |
| amount    | uint                                             |
| max-fee   | uint                                             |
| sender    | principal                                        |
| recipient | (tuple (hashbytes (buff 32)) (version (buff 1))) |
| height    | uint                                             |

### complete-deposit

[View in file](../contracts/sbtc-registry.clar#L152)

`(define-public (complete-deposit ((txid (buff 32)) (vout-index uint) (amount uint) (recipient principal)) (response bool uint))`

Store a new insert request.
Note that this function can only be called by other sBTC
contracts (specifically the current version of the deposit contract)

- it cannot be called by users directly.

This function does not handle validation or moving the funds.
Instead, it is purely for the purpose of storing the completed deposit.

<details>
  <summary>Source code:</summary>

```clarity
(define-public (complete-deposit
    (txid (buff 32))
    (vout-index uint)
    (amount uint)
    (recipient principal)
  )
  (begin
    (try! (validate-caller))
    (map-insert completed-deposits {txid: txid, vout-index: vout-index} {
      amount: amount,
      recipient: recipient
    })
    (print {
      topic: "completed-deposit",
      txid: txid,
      vout-index: vout-index
    })
    (ok true)
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

### rotate-keys

[View in file](../contracts/sbtc-registry.clar#L175)

`(define-public (rotate-keys ((new-keys (list 15 (buff 32))) (new-address principal) (new-aggregate-pubkey (buff 32))) (response bool uint))`

Rotate the signer set, multi-sig principal, & aggregate pubkey
This function can only be called by the bootstrap-signers contract.

<details>
  <summary>Source code:</summary>

```clarity
(define-public (rotate-keys (new-keys (list 15 (buff 32))) (new-address principal) (new-aggregate-pubkey (buff 32)))
  (begin
    ;; Check that caller is protocol contract
    (try! (validate-caller))
    ;; Check that the aggregate pubkey is not already in the map
    (asserts! (map-insert aggregate-pubkeys new-aggregate-pubkey true) ERR_AGG_PUBKEY_REPLAY)
    ;; Check that the new address (multi-sig) is not already in the map
    (asserts! (map-insert multi-sig-address new-address true) ERR_MULTI_SIG_REPLAY)
    ;; Update the current signer set
    (var-set current-signer-set new-keys)
    ;; Update the current multi-sig address
    (var-set current-signer-principal new-address)
    ;; Update the current aggregate pubkey
    (ok (var-set current-aggregate-pubkey new-aggregate-pubkey))
  )
)
```

</details>

**Parameters:**

| Name                 | Type                |
| -------------------- | ------------------- |
| new-keys             | (list 15 (buff 32)) |
| new-address          | principal           |
| new-aggregate-pubkey | (buff 32)           |

### increment-last-withdrawal-request-id

[View in file](../contracts/sbtc-registry.clar#L196)

`(define-private (increment-last-withdrawal-request-id () uint)`

Increment the last withdrawal request ID and
return the new value.

<details>
  <summary>Source code:</summary>

```clarity
(define-private (increment-last-withdrawal-request-id)
  (let
    (
      (next-value (+ u1 (var-get last-withdrawal-request-id)))
    )
    (var-set last-withdrawal-request-id next-value)
    next-value
  )
)
```

</details>

### validate-caller

[View in file](../contracts/sbtc-registry.clar#L209)

`(define-private (validate-caller () (response bool uint))`

Validate the caller of the function.
TODO: Once other contracts are in place, update this
to use the sBTC controller.

<details>
  <summary>Source code:</summary>

```clarity
(define-private (validate-caller)
  ;; To provide an explicit error type, add a branch that
  ;; wont be hit
  ;; (if (is-eq contract-caller .controller) (ok true) (err ERR_UNAUTHORIZED))
  (if false ERR_UNAUTHORIZED (ok true))
)
```

</details>

## Maps

### withdrawal-requests

Maps
Internal data structure to store withdrawal
requests. Requests are associated with a unique
request ID.

```clarity
(define-map withdrawal-requests uint {
  ;; Amount of sBTC being withdrawaled (in sats)
  amount: uint,
  max-fee: uint,
  sender: principal,
  ;; BTC recipient address in the same format of
  ;; pox contracts
  recipient: {
    version: (buff 1),
    hashbytes: (buff 32),
  },
  ;; Burn block height where the withdrawal request was
  ;; created
  block-height: uint,
})
```

[View in file](../contracts/sbtc-registry.clar#L20)

### withdrawal-status

Data structure to map request-id to status
If status is `none`, the request is pending.
Otherwise, the boolean value indicates whether
the deposit was accepted.

```clarity
(define-map withdrawal-status uint bool)
```

[View in file](../contracts/sbtc-registry.clar#L40)

### completed-deposits

Internal data structure to store completed
deposit requests & avoid replay attacks.

```clarity
(define-map completed-deposits {txid: (buff 32), vout-index: uint}
  {
    amount: uint,
    recipient: principal
  }
)
```

[View in file](../contracts/sbtc-registry.clar#L44)

### aggregate-pubkeys

Data structure to store aggregate pubkey,
stored to avoid replay

```clarity
(define-map aggregate-pubkeys (buff 32) bool)
```

[View in file](../contracts/sbtc-registry.clar#L53)

### multi-sig-address

Data structure to store the current signer set,
stored to avoid replay

```clarity
(define-map multi-sig-address principal bool)
```

[View in file](../contracts/sbtc-registry.clar#L57)

## Variables

### last-withdrawal-request-id

uint

Variables

```clarity
(define-data-var last-withdrawal-request-id uint u0)
```

[View in file](../contracts/sbtc-registry.clar#L10)

### current-signer-set

(list 15 (buff 32))

```clarity
(define-data-var current-signer-set (list 15 (buff 32)) (list))
```

[View in file](../contracts/sbtc-registry.clar#L11)

### current-aggregate-pubkey

(buff 32)

```clarity
(define-data-var current-aggregate-pubkey (buff 32) 0x00)
```

[View in file](../contracts/sbtc-registry.clar#L12)

### current-signer-principal

principal

```clarity
(define-data-var current-signer-principal principal tx-sender)
```

[View in file](../contracts/sbtc-registry.clar#L13)

## Constants

### ERR_UNAUTHORIZED

Error codes

```clarity
(define-constant ERR_UNAUTHORIZED (err u400))
```

[View in file](../contracts/sbtc-registry.clar#L4)

### ERR_INVALID_REQUEST_ID

```clarity
(define-constant ERR_INVALID_REQUEST_ID (err u401))
```

[View in file](../contracts/sbtc-registry.clar#L5)

### ERR_AGG_PUBKEY_REPLAY

```clarity
(define-constant ERR_AGG_PUBKEY_REPLAY (err u402))
```

[View in file](../contracts/sbtc-registry.clar#L6)

### ERR_MULTI_SIG_REPLAY

```clarity
(define-constant ERR_MULTI_SIG_REPLAY (err u403))
```

[View in file](../contracts/sbtc-registry.clar#L7)
