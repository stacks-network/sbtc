;; Properties

(define-constant ERR_ASSERTION_FAILED (err u1001))
(define-constant ERR_UNWRAP_FAILURE (err u1002))

(define-constant deployer tx-sender)
(define-constant dust_limit_error_code u502)

;; This is a test utility, not an assertion. It randomly mints sbtc-tokens to
;; users, supporting other tests.
(define-public (test-mint (amount uint) (recipient principal))
  (if
    (or 
      (not (is-eq deployer tx-sender))
      (is-eq amount u0)
    )
    (ok false)
    (contract-call? .sbtc-token protocol-mint amount recipient)))

(define-public (test-initiate-withdrawal-locked-balance
    (amount uint)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (max-fee uint)
  )
  (if
    (or
      (is-eq amount u0)
      (<= amount DUST_LIMIT)
      (<
        (unwrap-panic
          (contract-call? .sbtc-token get-balance-available tx-sender)
        )
        (+ amount max-fee)
      )
      (is-err (validate-recipient recipient))
    )
    (ok false)
    (let
      (
        (balance-locked-before
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-locked tx-sender)
          )
        )
      )
      (try! (initiate-withdrawal-request amount recipient max-fee))
      (asserts!
        (is-eq
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-locked tx-sender)
          )
          (+ balance-locked-before amount max-fee)
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-initiate-withdrawal-available-balance
    (amount uint)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (max-fee uint)
  )
  (if
    (or
      (is-eq amount u0)
      (<= amount DUST_LIMIT)
      (<
        (unwrap-panic
          (contract-call? .sbtc-token get-balance-available tx-sender)
        )
        (+ amount max-fee)
      )
      (is-err (validate-recipient recipient))
    )
    (ok false)
    (let
      (
        (balance-available-before
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-available tx-sender)
          )
        )
      )
      (try! (initiate-withdrawal-request amount recipient max-fee))
      (asserts!
       (is-eq
          (unwrap-panic
            (contract-call? .sbtc-token get-balance-available tx-sender)
          )
          (- balance-available-before amount max-fee)
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)

(define-public (test-initiate-withdrawal-dust-amount
    (amount uint)
    (recipient { version: (buff 1), hashbytes: (buff 32) })
    (max-fee uint)
  )
  (if
    (or
      (is-eq amount u0)
      (> amount DUST_LIMIT)
      (<
        (unwrap-panic
          (contract-call? .sbtc-token get-balance-available tx-sender)
        )
        (+ amount max-fee)
      )
    )
    (ok false)
    (let
      (
        (withdrawal-request-result
          (initiate-withdrawal-request amount recipient max-fee)
        )
      )
      (asserts!
        (and
          (is-err withdrawal-request-result)
          (is-eq
            (unwrap-err! withdrawal-request-result ERR_UNWRAP_FAILURE)
            dust_limit_error_code
          )
        )
        ERR_ASSERTION_FAILED
      )
      (ok true)
    )
  )
)