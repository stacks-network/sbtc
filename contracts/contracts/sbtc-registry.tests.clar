;; Invariants

(define-constant deployer tx-sender)

(define-read-only (invariant-signers-always-protocol-caller)
  (unwrap-panic (map-get? protocol-contracts .sbtc-bootstrap-signers)))

(define-read-only (invariant-deposit-always-protocol-caller)
  (unwrap-panic (map-get? protocol-contracts .sbtc-deposit)))

(define-read-only (invariant-withdrawal-always-protocol-caller)
  (unwrap-panic (map-get? protocol-contracts .sbtc-withdrawal)))

(define-read-only (invariant-protocol-caller-some-true (caller principal))
  (if (is-some (map-get? protocol-contracts caller))
    (unwrap-panic (map-get? protocol-contracts caller))
    true))

(define-read-only (invariant-withdraw-req-id-some (id uint))
  (if
    (and
      (<= id (var-get last-withdrawal-request-id))
      (> id u0))
    (is-some (map-get? withdrawal-requests id))
    true))

(define-read-only (invariant-withdraw-req-id-none (id uint))
  (if
    (or
      (> id (var-get last-withdrawal-request-id))
      (is-eq id u0))
    (is-none (map-get? withdrawal-requests id))
    true))

(define-read-only (invariant-last-withraw-req-id-eq-calls)
  (let (
      (num-calls-withdraw-req
        (default-to
          u0
          (get called (map-get? context "create-withdrawal-request"))))
    )
    (is-eq (var-get last-withdrawal-request-id) num-calls-withdraw-req)))

(define-read-only (invariant-withdrawal-status-none (req-id uint))
  (let (
      (num-calls-withdraw-accept
        (default-to
          u0
          (get called (map-get? context "complete-withdrawal-accept"))))
      (num-calls-withdraw-reject
        (default-to
          u0
          (get called (map-get? context "complete-withdrawal-reject"))))
    )
    (if
      (and
        (is-eq num-calls-withdraw-accept u0)
        (is-eq num-calls-withdraw-reject u0))
      (is-none (map-get? withdrawal-status req-id))
      true)))

(define-read-only (invariant-current-sig-threshold-unchanged)
  (let (
      (num-calls-rotate-keys
        (default-to u0 (get called (map-get? context "rotate-keys"))))
    )
    (if
      (is-eq num-calls-rotate-keys u0)
      (is-eq (var-get current-signature-threshold) u0)
      true)))

(define-read-only (invariant-current-sig-principal-unchanged)
  (let (
      (num-calls-rotate-keys
        (default-to u0 (get called (map-get? context "rotate-keys"))))
    )
    (if 
      (is-eq num-calls-rotate-keys u0)
      (is-eq (var-get current-signer-principal) deployer)
      true)))

(define-read-only (invariant-current-agg-pubkey-unchanged)
  (let (
      (num-calls-rotate-keys
        (default-to u0 (get called (map-get? context "rotate-keys"))))
    )
    (if 
      (is-eq num-calls-rotate-keys u0)
      (is-eq (var-get current-aggregate-pubkey) 0x00)
      true)))

(define-read-only (invariant-multi-sig-address-true)
  (let (
      (num-calls-rotate-keys (default-to u0 (get called (map-get? context "rotate-keys"))))
    )
    (if
      (> num-calls-rotate-keys u0)
      (unwrap-panic (map-get? multi-sig-address (var-get current-signer-principal)))
      true)))

;; Properties

(define-constant ERR_WRONG_ERROR_CODE (err u1000))
(define-constant ERR_ASSERTION_FAILED (err u1001))

(define-public (test-is-protocol-caller-ok (caller principal))
  (if
    (not (is-eq deployer caller))
    (ok false)
    (let
      (
        (is-protocol-caller-result (validate-protocol-caller caller))
      )
      (asserts! (is-ok is-protocol-caller-result) ERR_ASSERTION_FAILED)
      (ok true)
    )
  )
)

(define-public (test-is-protocol-caller-err (caller principal))
  (if
    (is-eq deployer caller)
    (ok false)
    (let
      (
        (unwrap-error (err u9999))
        (is-protocol-caller-result (validate-protocol-caller caller))
      )
      (asserts!
        (and
          (is-err is-protocol-caller-result)
          (is-eq
            (unwrap-err! is-protocol-caller-result unwrap-error)
            u400
          )
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-complete-withdrawal-reject
    (request-id uint)
    (signer-bitmap uint)
  )
  (if
    (not (is-eq deployer contract-caller))
    (ok false)
    (begin
      (try! (complete-withdrawal-reject request-id signer-bitmap))
      (asserts!
        (is-eq
          (unwrap-panic (map-get? withdrawal-status request-id))
          false
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-withdrawal-req-id-incremented
    (amount uint)
    (max-fee uint)
    (sender principal)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (height uint)
  )
  (if
    (not (is-eq deployer contract-caller))
    (ok false)
    (let
      (
        (last-withdrawal-req-id-before (var-get last-withdrawal-request-id))
      )
      (try! (create-withdrawal-request amount max-fee sender recipient height))
      (asserts!
        (is-eq
          (var-get last-withdrawal-request-id)
          (+ last-withdrawal-req-id-before u1)
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-withdrawal-req-id-non-deployer
    (amount uint)
    (max-fee uint)
    (sender principal)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (height uint)
  )
  (if
    (is-eq deployer contract-caller)
    (ok false)
    (let
      (
        (unwrap-error (err u9999))
        (withdrawal-request-result
          (create-withdrawal-request amount max-fee sender recipient height)
        )
      )
      (asserts!
        (is-eq
          (unwrap-err! withdrawal-request-result unwrap-error)
          u400
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-withdrawal-req-id-not-updated-non-deployer
    (amount uint)
    (max-fee uint)
    (sender principal)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (height uint)
  )
  (if
    (is-eq deployer contract-caller)
    (ok false)
    (let
      (
        (last-withdrawal-req-id-before (var-get last-withdrawal-request-id))
        (withdrawal-request-result
          (create-withdrawal-request amount max-fee sender recipient height)
        )
      )
      (asserts!
        (is-eq
          (var-get last-withdrawal-request-id)
          last-withdrawal-req-id-before
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)