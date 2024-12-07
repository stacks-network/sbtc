;; sBTC Registry contract

;; Error codes

(define-constant ERR_UNAUTHORIZED (err u400))
(define-constant ERR_INVALID_REQUEST_ID (err u401))
(define-constant ERR_AGG_PUBKEY_REPLAY (err u402))
(define-constant ERR_MULTI_SIG_REPLAY (err u403))
(define-constant ERR_INVALID_PROTOCOL_ID (err u404))


;; protocol contract type
(define-constant governance-role 0x00)
(define-constant deposit-role 0x01)
(define-constant withdrawal-role 0x02)

;; Variables

(define-data-var last-withdrawal-request-id uint u0)
(define-data-var current-signature-threshold uint u0)
(define-data-var current-signer-set (list 128 (buff 33)) (list))
(define-data-var current-aggregate-pubkey (buff 33) 0x00)
(define-data-var current-signer-principal principal tx-sender)
(define-data-var active-protocol-contracts {governance: principal, deposit: principal, withdrawal: principal} {
    governance: .sbtc-bootstrap-signers,
    deposit: .sbtc-deposit,
    withdrawal: .sbtc-withdrawal
})


;; Maps

;; Internal data structure to store withdrawal
;; requests. Requests are associated with a unique
;; request ID.
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

;; Data structure to map request-id to status
;; If status is `none`, the request is pending.
;; Otherwise, the boolean value indicates whether
;; the withdrawal was accepted.
(define-map withdrawal-status uint bool)

;; Data structure to map successful withdrawal requests
;; to their respective sweep transaction. Stores the 
;; txid, burn hash, and burn height.
(define-map completed-withdrawal-sweep uint {
  sweep-txid: (buff 32),
  sweep-burn-hash: (buff 32),
  sweep-burn-height: uint,
})

;; Internal data structure to store completed
;; deposit requests & avoid replay attacks.
(define-map deposit-status {txid: (buff 32), vout-index: uint} bool)

;; Data structure to map successful deposit requests
;; to their respective sweep transaction. Stores the
;; txid, burn hash, and burn height.
(define-map completed-deposits {txid: (buff 32), vout-index: uint}
  {
    amount: uint,
    recipient: principal,
    sweep-txid: (buff 32),
    sweep-burn-hash: (buff 32),
    sweep-burn-height: uint,
  }
)

;; Data structure to store aggregate pubkey,
;; stored to avoid replay
(define-map aggregate-pubkeys (buff 33) bool)

;; Read-only functions
;; Get a withdrawal request by its ID.
;; This function returns the fields of the withdrawal
;; request, along with its status.
(define-read-only (get-withdrawal-request (id uint))
  (match (map-get? withdrawal-requests id)
    request (some (merge request {
      status: (map-get? withdrawal-status id)
    }))
    none
  )
)

;; Get a completed withdrawal sweep data by its request ID.
;; This function returns the fields of the withdrawal-sweeps map.
(define-read-only (get-completed-withdrawal-sweep-data (id uint))
  (map-get? completed-withdrawal-sweep id)
)

;; Get a completed deposit by its transaction ID & vout index.
;; This function returns the fields of the completed-deposits map.
(define-read-only (get-completed-deposit (txid (buff 32)) (vout-index uint))
  (map-get? completed-deposits {txid: txid, vout-index: vout-index})
)

;; Get a completed deposit sweep data by its transaction ID & vout index.
;; This function returns the fields of the completed-deposits map.
(define-read-only (get-deposit-status (txid (buff 32)) (vout-index uint))
  (map-get? deposit-status {txid: txid, vout-index: vout-index})
)

;; Get the current signer set.
;; This function returns the current signer set as a list of principals.
(define-read-only (get-current-signer-data)
  {
    current-signer-set: (var-get current-signer-set),
    current-aggregate-pubkey: (var-get current-aggregate-pubkey),
    current-signer-principal: (var-get current-signer-principal),
    current-signature-threshold: (var-get current-signature-threshold),
  }
)

;; Get the current aggregate pubkey.
;; This function returns the current aggregate pubkey.
(define-read-only (get-current-aggregate-pubkey)
  (var-get current-aggregate-pubkey)
)

;; Get the current signer principal.
;; This function returns the current signer principal.
(define-read-only (get-current-signer-principal)
  (var-get current-signer-principal)
)

(define-read-only (get-current-signer-set)
  (var-get current-signer-set)
)

(define-read-only (get-active-protocol-contracts)
  (var-get active-protocol-contracts)
)


;; Public functions

;; Store a new withdrawal request.
;; Note that this function can only be called by other sBTC
;; contracts - it cannot be called by users directly.
;; 
;; This function does not handle validation or moving the funds.
;; Instead, it is purely for the purpose of storing the request.
;; 
;; The function will emit a print event with the topic "withdrawal-create"
;; and the data of the request.
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
    (try! (is-protocol-caller (some withdrawal-role)))
    ;; #[allow(unchecked_data)]
    (map-insert withdrawal-requests id {
      amount: amount,
      max-fee: max-fee,
      sender: sender,
      recipient: recipient,
      block-height: height,
    })
    (print {
      topic: "withdrawal-create",
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

;; Complete withdrawal request by noting the acceptance in the
;; withdrawal-status state map.
;;
;; This function will emit a print event with the topic
;; "withdrawal-accept".
(define-public (complete-withdrawal-accept
    (request-id uint) 
    (bitcoin-txid (buff 32))
    (output-index uint)
    (signer-bitmap uint)
    (fee uint)
    (burn-hash (buff 32))
    (burn-height uint)
    (sweep-txid (buff 32))
  )
  (begin 
    (try! (is-protocol-caller (some withdrawal-role)))
    ;; Mark the withdrawal as completed
    (map-insert withdrawal-status request-id true)
    (map-insert completed-withdrawal-sweep request-id {
      sweep-txid: sweep-txid,
      sweep-burn-hash: burn-hash,
      sweep-burn-height: burn-height,
    })
    (print {
      topic: "withdrawal-accept",
      request-id: request-id,
      bitcoin-txid: bitcoin-txid,
      signer-bitmap: signer-bitmap,
      output-index: output-index,
      fee: fee,
      burn-hash: burn-hash,
      burn-height: burn-height,
      sweep-txid: sweep-txid,
    })
    (ok true)
  )
)

;; Complete withdrawal request by noting the rejection in the 
;; withdrawal-status state map.
;;
;; This function will emit a print event with the topic
;; "withdrawal-reject".
(define-public (complete-withdrawal-reject
    (request-id uint) 
    (signer-bitmap uint)
  )
  (begin 
    (try! (is-protocol-caller (some withdrawal-role)))
    ;; Mark the withdrawal as completed
    (map-insert withdrawal-status request-id false)
    (print {
      topic: "withdrawal-reject",
      request-id: request-id,
      signer-bitmap: signer-bitmap,
    })
    (ok true)
  )
)

;; Store a new insert request.
;; Note that this function can only be called by other sBTC
;; contracts (specifically the current version of the deposit contract) 
;; - it cannot be called by users directly.
;; 
;; This function does not handle validation or moving the funds.
;; Instead, it is purely for the purpose of storing the completed deposit.
(define-public (complete-deposit
    (txid (buff 32))
    (vout-index uint)
    (amount uint)
    (recipient principal)
    (burn-hash (buff 32))
    (burn-height uint)
    (sweep-txid (buff 32))
  )
  (begin
    (try! (is-protocol-caller (some deposit-role)))
    (map-insert deposit-status {txid: txid, vout-index: vout-index} true)
    (map-insert completed-deposits {txid: txid, vout-index: vout-index} {
      amount: amount,
      recipient: recipient,
      sweep-txid: sweep-txid,
      sweep-burn-hash: burn-hash,
      sweep-burn-height: burn-height,
    })
    (print {
      topic: "completed-deposit",
      bitcoin-txid: txid,
      output-index: vout-index,
      amount: amount,
      burn-hash: burn-hash,
      burn-height: burn-height,
      sweep-txid: sweep-txid,
    })
    (ok true)
  )
)

;; Rotate the signer set, multi-sig principal, & aggregate pubkey
;; This function can only be called by the bootstrap-signers contract.
(define-public (rotate-keys 
    (new-keys (list 128 (buff 33)))
    (new-address principal)
    (new-aggregate-pubkey (buff 33))
    (new-signature-threshold uint)
  )
  (begin
    ;; Check that caller is protocol contract
    (try! (is-protocol-caller (some governance-role)))
    ;; Check that the aggregate pubkey is not already in the map
    (asserts! (map-insert aggregate-pubkeys new-aggregate-pubkey true) ERR_AGG_PUBKEY_REPLAY)
    ;; Update the current signer set
    (var-set current-signer-set new-keys)
    ;; Update the current multi-sig address
    (var-set current-signer-principal new-address)
    ;; Update the current signature threshold
    (var-set current-signature-threshold new-signature-threshold)
    ;; Update the current aggregate pubkey
    (var-set current-aggregate-pubkey new-aggregate-pubkey)
    (print {
      topic: "key-rotation",
      new-keys: new-keys,
      new-address: new-address,
      new-aggregate-pubkey: new-aggregate-pubkey,
      new-signature-threshold: new-signature-threshold
    })
    (ok true)
  )
)

;; Update protocol contract
;; This function can only be called by the active bootstrap-signers contract
(define-public (update-protocol-contract
    (contract-type (buff 1))
    (new-contract principal)
  )
  (let
    (
      (active-contracts (var-get active-protocol-contracts))
    )
    ;; Check that caller is protocol contract
    (try! (is-protocol-caller (some governance-role)))
    (asserts! (and (>= contract-type governance-role) (<= contract-type withdrawal-role)) ERR_INVALID_PROTOCOL_ID)
    (if (is-eq contract-type governance-role)
      (var-set active-protocol-contracts (merge active-contracts {governance: new-contract}))
      (if (is-eq contract-type deposit-role)
        (var-set active-protocol-contracts (merge active-contracts {deposit: new-contract}))
        (var-set active-protocol-contracts (merge active-contracts {withdrawal: new-contract}))
      )
    )
    (print {
      topic: "update-protocol-contract",
      contract-type: contract-type,
      new-contract: new-contract,
    })
    (ok true)
  )
)

;; Private functions
;; Increment the last withdrawal request ID and
;; return the new value.
(define-private (increment-last-withdrawal-request-id)
  (let
    (
      (next-value (+ u1 (var-get last-withdrawal-request-id)))
    )
    (var-set last-withdrawal-request-id next-value)
    next-value
  )
)

;; Checks whether the contract-caller is a protocol contract
(define-read-only (is-protocol-caller (contract-flag (optional (buff 1))))
  (validate-protocol-caller contract-flag contract-caller)
)

;; Validate that a given principal is a protocol contract
(define-read-only (validate-protocol-caller (contract-flag (optional (buff 1))) (caller principal))
  (let 
    (
      (active-contracts (var-get active-protocol-contracts))
    )
    (match contract-flag 
      flag
      (ok (asserts! 
        (if (is-eq flag governance-role)
          (is-eq caller (get governance active-contracts))
          (if (is-eq flag deposit-role)
            (is-eq caller (get deposit active-contracts))
            (if (is-eq flag withdrawal-role)
              (is-eq caller (get withdrawal active-contracts))
              false
            )
          )
        )
      ERR_UNAUTHORIZED))
      (ok (asserts! (or 
        (is-eq caller (get governance active-contracts))
        (is-eq caller (get deposit active-contracts))
        (is-eq caller (get withdrawal active-contracts))
      ) ERR_UNAUTHORIZED))
    )
  )
)
