# sbtc-registry

[`sbtc-registry.clar`](../contracts/sbtc-registry.clar)

sBTC Registry contract

**Public functions:**

- [`create-withdrawal-request`](#create-withdrawal-request)

**Read-only functions:**

**Private functions:**

- [`increment-last-withdrawal-request-id`](#increment-last-withdrawal-request-id)
- [`validate-caller`](#validate-caller)

**Maps**

- [`withdrawal-requests`](#withdrawal-requests)
- [`withdrawal-status`](#withdrawal-status)

**Variables**

- [`last-withdrawal-request-id`](#last-withdrawal-request-id)

**Constants**

- [`ERR_UNAUTHORIZED`](#err_unauthorized)

## Functions

### create-withdrawal-request

[View in file](../contracts/sbtc-registry.clar#L46)

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

### increment-last-withdrawal-request-id

[View in file](../contracts/sbtc-registry.clar#L83)

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

[View in file](../contracts/sbtc-registry.clar#L96)

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
  (if false (err ERR_UNAUTHORIZED) (ok true))
)
```

</details>

## Maps

### withdrawal-requests

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

[View in file](../contracts/sbtc-registry.clar#L11)

### withdrawal-status

Data structure to map request-id to status
If status is `none`, the request is pending.
Otherwise, the boolean value indicates whether
the deposit was accepted.

```clarity
(define-map withdrawal-status uint bool)
```

[View in file](../contracts/sbtc-registry.clar#L33)

## Variables

### last-withdrawal-request-id

uint

```clarity
(define-data-var last-withdrawal-request-id uint u0)
```

[View in file](../contracts/sbtc-registry.clar#L27)

## Constants

### ERR_UNAUTHORIZED

Thrown when the contract caller is not authorized

```clarity
(define-constant ERR_UNAUTHORIZED u400)
```

[View in file](../contracts/sbtc-registry.clar#L6)
