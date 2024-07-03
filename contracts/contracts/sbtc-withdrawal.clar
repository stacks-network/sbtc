;; Error codes

;; The `version` part of the recipient address is invalid
(define-constant ERR_INVALID_ADDR_VERSION (err u500))
;; The `hashbytes` part of the recipient address is invalid
(define-constant ERR_INVALID_ADDR_HASHBYTES (err u501))
;; The size of the withdrawal is smaller than the dust limit
(define-constant ERR_DUST_LIMIT (err u502))
;; The request id was invalid / returned 'none'
(define-constant ERR_INVALID_REQUEST (err u503))
;; The caller is not the currently-governing multisig principal
(define-constant ERR_INVALID_CALLER (err u504))
;; The withdrawal request was already processed
(define-constant ERR_ALREADY_PROCESSED (err u505))
;; The paid fee was higher than requested
(define-constant ERR_FEE_TOO_HIGH (err u505))
;; The returned index marks the failed transaction in list
(define-constant ERR_WITHDRAWAL_INDEX_PREFIX (unwrap-err! ERR_WITHDRAWAL_INDEX (err true)))
(define-constant ERR_WITHDRAWAL_INDEX (err u506))

;; Maximum value of an address version as a uint
(define-constant MAX_ADDRESS_VERSION u6)
;; Maximum value of an address version that has a 20-byte hashbytes
;; (0x00, 0x01, 0x02, 0x03, and 0x04 have 20-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_20 u4)
;; Maximum value of an address version that has a 32-byte hashbytes
;; (0x05 and 0x06 have 32-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_32 u6)
;; The minimum amount of sBTC you can withdraw
(define-constant DUST_LIMIT u546)

;; Initiate a new withdrawal request
(define-public (initiate-withdrawal-request (amount uint)
                                            (recipient { version: (buff 1), hashbytes: (buff 32) })
                                            (max-fee uint)
  )
  (begin
    (try! (contract-call? .sbtc-token protocol-lock amount tx-sender))
    (asserts! (> amount DUST_LIMIT) ERR_DUST_LIMIT)
  
    ;; Validate the recipient address
    (try! (validate-recipient recipient))
    
    (ok (try! (contract-call? .sbtc-registry create-withdrawal-request amount max-fee tx-sender recipient burn-block-height)))
  )
)

;; Accept a withdrawal request
(define-public (accept-withdrawal-request (request-id uint) 
                                          (bitcoin-txid (buff 32)) 
                                          (signer-bitmap uint)
                                          (output-index uint)
                                          (fee uint))
  (let 
    (
      (current-signer-data (contract-call? .sbtc-registry get-current-signer-data))   
      (request  (unwrap! (contract-call? .sbtc-registry get-withdrawal-request request-id) ERR_INVALID_REQUEST))
      (requested-max-fee (get max-fee request))
      (requester (get sender request))
    )
      ;; Check that the caller is the current signer principal
      (asserts! (is-eq (get current-signer-principal current-signer-data) tx-sender) ERR_INVALID_CALLER)

      ;; Check whether it was already accepted or rejected
      (asserts! (is-none (get status request)) ERR_ALREADY_PROCESSED)

      ;; Check that fee is not higher than requesters max fee
      (asserts! (<= fee requested-max-fee) ERR_FEE_TOO_HIGH)

      ;; Burn the locked-sbtc
      (try! (contract-call? .sbtc-token protocol-burn-locked (get amount request) requester))

      ;; Mint the difference b/w max-fee of the request & fee actually paid back to the user in sBTC
      (if (is-eq (- requested-max-fee fee) u0)
        true
        (try! (contract-call? .sbtc-token protocol-mint (- requested-max-fee fee) requester))
      )

      ;; Call into registry to confirm accepted withdrawal
      (try! (contract-call? .sbtc-registry complete-withdrawal request-id true (some bitcoin-txid) (some signer-bitmap) (some output-index) (some fee)))

      (ok true)
  )
)

;; Reject a withdrawal request
(define-public (reject-withdrawal-request (request-id uint) (signer-bitmap uint))
  (let
     (
      (current-signer-data (contract-call? .sbtc-registry get-current-signer-data))   
      (withdrawal (unwrap! (contract-call? .sbtc-registry get-withdrawal-request request-id) ERR_INVALID_REQUEST))
     )

    ;; Check that the caller is the current signer principal
    (asserts! (is-eq (get current-signer-principal current-signer-data) tx-sender) ERR_INVALID_CALLER)

    ;; Check that request status is currently-pending
    (asserts! (is-none (get status withdrawal)) ERR_ALREADY_PROCESSED)

    ;; Burn sbtc-locked & re-mint sbtc to original requester
    (try! (contract-call? .sbtc-token protocol-unlock (get amount withdrawal) (get sender withdrawal)))

    ;; Call into registry to confirm accepted withdrawal
    (try! (contract-call? .sbtc-registry complete-withdrawal request-id false none (some signer-bitmap) none none))

    (ok true)
  )
)
;; Reject multiple withdrawal requests
(define-public (complete-withdrawals (withdrawals (list 100 
                                     {request-id: uint, 
                                     status: bool, 
                                     signer-bitmap: uint, 
                                     bitcoin-txid: (optional (buff 32)), 
                                     output-index: (optional uint), 
                                     fee: (optional uint)})))
  (let 
      (
          (current-signer-data (contract-call? .sbtc-registry get-current-signer-data))
      )

      ;; Check that the caller is the current signer principal
      (asserts! (is-eq (get current-signer-principal current-signer-data) tx-sender) ERR_INVALID_CALLER)

      (fold complete-individual-withdrawal-helper withdrawals (ok u0))
  )
)

(define-private (complete-individual-withdrawal-helper (withdrawal 
                                                        {request-id: uint, 
                                                        status: bool, 
                                                        signer-bitmap: uint, 
                                                        bitcoin-txid: (optional (buff 32)), 
                                                        output-index: (optional uint), 
                                                        fee: (optional uint)}) 
                                                       (helper-response (response uint uint)))
  (match helper-response 
    index
      (let
        (
          (current-request-id (get request-id withdrawal))
          (current-signer-bitmap (get signer-bitmap withdrawal))
          (current-bitcoin-txid (get bitcoin-txid withdrawal))
          (current-output-index (get output-index withdrawal))
          (current-fee (get fee withdrawal))
        ) 
        (if (get status withdrawal)
          ;; accepted
          (begin 
            (asserts! 
              (and (is-some current-bitcoin-txid) (is-some current-output-index) (is-some current-fee)) 
              (err (+ ERR_WITHDRAWAL_INDEX_PREFIX (+ u10 index))))
            (unwrap! (accept-withdrawal-request (get request-id withdrawal) (unwrap-panic current-bitcoin-txid) current-signer-bitmap (unwrap-panic current-output-index) (unwrap-panic current-fee)) (err (+ ERR_WITHDRAWAL_INDEX_PREFIX (+ u10 index))))
          )
          ;; rejected
          (unwrap! (reject-withdrawal (get request-id withdrawal) current-signer-bitmap) (err (+ ERR_WITHDRAWAL_INDEX_PREFIX (+ u10 index))))
        )
        (ok (+ index u1))
      )
    err-response
            (err err-response)
  )
)

;; Validation methods

;; Validate that a withdrawal's recipient address is well-formed.
;; The logic here follows the same rules as pox-4.
;; 
;; At a high-level, the version must be a uint between 0 and 6 (inclusive),
;; and the length of the hashbytes must be 20 bytes if the version is <= 4,
;; and 32 bytes if the version is 5 or 6.
(define-read-only (validate-recipient (recipient { version: (buff 1), hashbytes: (buff 32) }))
  (let
    (
      (version (get version recipient))
      (hashbytes (get hashbytes recipient))
      (version-int (buff-to-uint-be version))
    )
    ;; Validate the `version`
    (asserts! (<= version-int MAX_ADDRESS_VERSION) ERR_INVALID_ADDR_VERSION)
    ;; Validate the length of `hashbytes`
    (asserts! (if (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION_BUFF_20)
        ;; If version is <= 4, then hashbytes must be 20 bytes
        (is-eq (len hashbytes) u20)
        ;; Otherwise, hashbytes must be 32 bytes
        (is-eq (len hashbytes) u32))
      ERR_INVALID_ADDR_HASHBYTES)
    (ok true)
  )
)