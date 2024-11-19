;; Placeholder for property-based tests.
;; Add your test cases here.

(define-constant deployer tx-sender)

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