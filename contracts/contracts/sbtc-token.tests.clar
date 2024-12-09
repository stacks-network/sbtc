;; Invariants

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

;; Properties

(define-constant ERR_FAILED_ASSERTION (err u999))

(define-constant deployer tx-sender)

;; Protocol Mint
(define-public (test-protocol-mint-balance-increase (address principal) (amount uint))
  (let (
      (initial-balance (unwrap-panic (get-balance-available address)))
    )
    (ok
      (if
        (or (not (is-eq tx-sender deployer)) (is-eq amount u0))
        false
        (begin
          (try! (protocol-mint amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-available address))
              (+ initial-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Burn
(define-public (test-protocol-burn-balance-decrease (address principal) (amount uint))
  (let (
      (initial-balance (unwrap-panic (get-balance-available address)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq amount u0)
          (> amount initial-balance))
        false
        (begin
          (try! (protocol-burn amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-available address))
              (- initial-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Transfer
(define-public (test-transfer-balance-sender (amount uint)
                                              (recipient principal)
                                              (memo (optional (buff 34))))
  (let (
      (sender-balance-before
        (unwrap-panic
          (get-balance-available tx-sender)))
    )
    (ok
      (if
        (or
          (is-eq tx-sender recipient)
          (> amount sender-balance-before)
          (is-eq amount u0))
        false
        (begin
          (try! (transfer amount tx-sender recipient memo))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-available tx-sender))
              (- sender-balance-before amount))
            ERR_FAILED_ASSERTION)
          true))))
)

(define-public (test-transfer-balance-recipient (amount uint)
                                                (recipient principal)
                                                (memo (optional (buff 34))))
  (let (
      (sender-balance-before (unwrap-panic (get-balance-available tx-sender)))
      (recipient-balance-before
        (unwrap-panic (get-balance-available recipient)))
    )
    (ok
      (if
        (or
          (is-eq tx-sender recipient)
          (> amount sender-balance-before)
          (is-eq amount u0))
        false
        (begin
          (try!
            (transfer amount tx-sender recipient memo))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-available recipient))
              (+ recipient-balance-before amount))
            ERR_FAILED_ASSERTION)
          true))))
)

;; Protocol Lock
(define-public (test-protocol-lock-locked-balance (address principal)
                                                  (amount uint))
  (let (
      (initial-balance (unwrap-panic (get-balance-available address)))
      (initial-locked-balance (unwrap-panic (get-balance-locked address)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq amount u0)
          (> amount initial-balance))
        false
        (begin
          (try! (protocol-lock amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-locked address))
              (+ initial-locked-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

(define-public (test-protocol-lock-available-balance (address principal)
                                                    (amount uint))
  (let (
      (initial-balance (unwrap-panic (get-balance-available address)))
      (initial-locked-balance (unwrap-panic (get-balance-locked address)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq amount u0)
          (> amount initial-balance))
        false
        (begin
          (try! (protocol-lock amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-available address))
              (- initial-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Unlock
(define-public (test-protocol-unlock-locked-balance (address principal)
                                                    (amount uint))
  (let (
      (initial-locked-balance (unwrap-panic (get-balance-locked address)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq amount u0)
          (> amount initial-locked-balance))
        false
        (begin
          (try! (protocol-unlock amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-locked address))
              (- initial-locked-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

(define-public (test-protocol-unlock-available-balance (address principal)
                                                      (amount uint))
  (let (
      (initial-available-balance (unwrap-panic (get-balance-available address)))
      (initial-locked-balance (unwrap-panic (get-balance-locked address)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq amount u0)
          (> amount initial-locked-balance))
        false
        (begin
          (try! (protocol-unlock amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-available address))
              (+ initial-available-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Burn Locked
(define-public (test-protocol-burn-locked-balance (address principal)
                                                  (amount uint))
  (let (
      (initial-locked-balance (unwrap-panic (get-balance-locked address)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq amount u0)
          (> amount initial-locked-balance))
        false
        (begin
          (try! (protocol-burn-locked amount address))
          (asserts!
            (is-eq
              (unwrap-panic (get-balance-locked address))
              (- initial-locked-balance amount))
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Set Name
(define-public (test-protocol-set-name (new-name (string-ascii 32)))
  (let (
      (initial-name (unwrap-panic (get-name)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq new-name initial-name))
        false
        (begin
          (try! (protocol-set-name new-name))
          (asserts!
            (is-eq
              (unwrap-panic (get-name))
              new-name)
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Set Token URI
(define-public (test-protocol-set-token-uri (new-uri (optional (string-utf8 256))))
  (let (
      (initial-uri (unwrap-panic (get-token-uri)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq initial-uri new-uri))
        false
        (begin
          (try! (protocol-set-token-uri new-uri))
          (asserts!
            (is-eq
              (unwrap-panic (get-token-uri))
              new-uri)
            ERR_FAILED_ASSERTION)
          true)))))

;; Protocol Set Symbol
(define-public (test-protocol-set-symbol (new-symbol (string-ascii 10)))
  (let (
      (initial-symbol (unwrap-panic (get-symbol)))
    )
    (ok
      (if
        (or
          (not (is-eq tx-sender deployer))
          (is-eq new-symbol initial-symbol))
        false
        (begin
          (try! (protocol-set-symbol new-symbol))
          (asserts!
            (is-eq
              (unwrap-panic (get-symbol))
              new-symbol)
            ERR_FAILED_ASSERTION)
          true)))))
