(define-read-only (invariant-total-supply-eq-locked-plus-unlocked)
  (is-eq
    (unwrap-panic (get-total-supply))
    (+ (ft-get-supply sbtc-token) (ft-get-supply sbtc-token-locked)))
)

(define-read-only (invariant-locked-lt-supply (address principal))
  (<=
    (ft-get-balance sbtc-token-locked address)
    (ft-get-supply sbtc-token-locked))
)

(define-read-only (invariant-unlocked-lt-supply (address principal))
  (<= (ft-get-balance sbtc-token address) (ft-get-supply sbtc-token))
)

(define-read-only (invariant-locked-supply-lt-total-supply)
  (<= (ft-get-supply sbtc-token-locked) (unwrap-panic (get-total-supply)))
)

(define-read-only (invariant-unlocked-supply-lt-total-supply)
  (<= (ft-get-supply sbtc-token) (unwrap-panic (get-total-supply)))
)

(define-read-only (invariant-token-uri-none)
  (let
    (
      (num-calls-set-token-uri
        (unwrap-panic
          (get called
            (map-get? context "protocol-set-token-uri"))))
    )
    (if
      (is-eq num-calls-set-token-uri u0)
      (is-none (var-get token-uri))
      true))
)

(define-read-only (invariant-supply-0-before-mint)
  (let
    (
      (num-calls-mint
        (unwrap-panic
          (get called (map-get? context "protocol-mint"))))
      (num-calls-mint-many
        (unwrap-panic
          (get called (map-get? context "protocol-mint-many"))))
    )
    (if
      (and (is-eq num-calls-mint u0) (is-eq num-calls-mint-many u0))
      (is-eq (unwrap-panic (get-total-supply)) u0)
      true))
)
