;; sBTC Registry contract

;; Error codes

(define-constant ERR_UNAUTHORIZED (err u400))
(define-constant ERR_INVALID_REQUEST_ID (err u401))
(define-constant ERR_AGG_PUBKEY_REPLAY (err u402))
(define-constant ERR_MULTI_SIG_REPLAY (err u403))

;; Variables

(define-data-var last-withdrawal-request-id uint u0)
(define-data-var current-signer-set (list 128 (buff 33)) (list))
(define-data-var current-aggregate-pubkey (buff 33) 0x00)
(define-data-var current-signer-principal principal tx-sender)


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
;; the deposit was accepted.
(define-map withdrawal-status uint bool)

;; Internal data structure to store completed
;; deposit requests & avoid replay attacks.
(define-map completed-deposits {txid: (buff 32), vout-index: uint}
  {
    amount: uint,
    recipient: principal
  }
)

;; Data structure to store aggregate pubkey,
;; stored to avoid replay
(define-map aggregate-pubkeys (buff 33) bool)

;; Data structure to store the current signer set,
;; stored to avoid replay
(define-map multi-sig-address principal bool)

;; Data structure to store the active protocol contracts
(define-map protocol-contracts principal bool)
(map-set protocol-contracts .sbtc-bootstrap-signers true)
(map-set protocol-contracts .sbtc-deposit true)
(map-set protocol-contracts .sbtc-withdrawal true)
(if (not is-in-mainnet) (map-set protocol-contracts tx-sender true) true)

;; Read-only functions
;; Get a withdrawal request by its ID.
;; This function returns the fields of the withrawal
;; request, along with its status.
(define-read-only (get-withdrawal-request (id uint))
  (match (map-get? withdrawal-requests id)
    request (some (merge request {
      status: (map-get? withdrawal-status id)
    }))
    none
  )
)

;; Get a completed deposit by its transaction ID & vout index.
;; This function returns the fields of the completed-deposits map.
(define-read-only (get-completed-deposit (txid (buff 32)) (vout-index uint))
  (map-get? completed-deposits {txid: txid, vout-index: vout-index})
)

;; Get the current signer set.
;; This function returns the current signer set as a list of principals.
(define-read-only (get-current-signer-data)
  {
    current-signer-set: (var-get current-signer-set),
    current-aggregate-pubkey: (var-get current-aggregate-pubkey),
    current-signer-principal: (var-get current-signer-principal)
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


;; Public functions

;; Store a new withdrawal request.
;; Note that this function can only be called by other sBTC
;; contracts - it cannot be called by users directly.
;; 
;; This function does not handle validation or moving the funds.
;; Instead, it is purely for the purpose of storing the request.
;; 
;; The function will emit a print event with the topic "withdrawal-request"
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

;; Complete withdrawal request
;; #[allow(unchecked_data)]
(define-public (complete-withdrawal
    (request-id uint) 
    (status bool)
    (bitcoin-txid (optional (buff 32))) 
    (signer-bitmap (optional uint))
    (output-index (optional uint))
    (fee (optional uint))
  )
  (begin 
    (try! (validate-caller))
    ;; Mark the withdrawal as completed
    (map-insert withdrawal-status request-id status)
    (print {
      topic: "completed-withdrawal",
      request-id: request-id,
      request-status: status,
      bitcoin-txid: bitcoin-txid,
      signer-bitmap: signer-bitmap,
      output-index: output-index,
      fee: fee
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
;; #[allow(unchecked_data)]
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
      vout-index: vout-index,
      amount: amount
    })
    (ok true)
  )
)

;; Rotate the signer set, multi-sig principal, & aggregate pubkey
;; This function can only be called by the bootstrap-signers contract.
;; #[allow(unchecked_data)]
(define-public (rotate-keys (new-keys (list 128 (buff 33))) (new-address principal) (new-aggregate-pubkey (buff 33)))
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

;; Validate the caller of the function.
;; TODO: Once other contracts are in place, update this
;; to use the sBTC controller.
(define-private (validate-caller)
  ;; To provide an explicit error type, add a branch that
  ;; wont be hit
  ;; (if (is-eq contract-caller .controller) (ok true) (err ERR_UNAUTHORIZED))
  (if false ERR_UNAUTHORIZED (ok true))
)

;; Checks whether the contract-caller is a protocol contract
(define-read-only (is-protocol-caller (principal-checked principal))
  (is-some (map-get? protocol-contracts principal-checked))
)

;; TODO: Add a function to add a protocol contract
;; TODO: Add a function to remove a protocol contract
