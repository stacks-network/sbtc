(define-constant err-no-sponsor (err u0))

(use-trait token-trait .trait-sip-010.sip-010-trait)

;; sponsored sBTC transfer (stx)
(define-public (sponsored-sbtc-transfer-stx (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))) (sponsor-fee-sbtc uint))
    (let
        ((sponsor (unwrap! tx-sponsor? err-no-sponsor)))
        ;; send sBTC to sponsor
        (try! (contract-call? .sbtc-token transfer sponsor-fee-sbtc sender sponsor none))
        ;; execute the sBTC transfer
        (try! (contract-call? .sbtc-token transfer amount sender recipient memo))
        (ok true)
    )
)

;; sponsored sBTC withdrawal (stx)
(define-public (sponsored-sbtc-withdrawal-stx (amount uint) (sender principal) (recipient { version: (buff 1), hashbytes: (buff 32) }) (memo (optional (buff 34))) (max-fee uint) (sponsor-fee-sbtc uint))
    (let
        ((sponsor (unwrap! tx-sponsor? err-no-sponsor)))
        ;; send sBTC to sponsor
        (try! (contract-call? .sbtc-token transfer sponsor-fee-sbtc sender sponsor none))
        ;; execute the sBTC request withdrawal
        (try! (contract-call? .sbtc-withdrawal initiate-withdrawal-request amount recipient max-fee))
        (ok true)
    )
)

;; sponsored sBTC transfer (sip10)
(define-public (sponsored-sbtc-transfer-sip10 (token <token-trait>) (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))) (sponsor-fee-sbtc uint))
    (let
        ((sponsor (unwrap! tx-sponsor? err-no-sponsor)))
        ;; send sBTC to sponsor
        (try! (contract-call? .sbtc-token transfer sponsor-fee-sbtc sender sponsor none))
        ;; execute the sBTC transfer
        (try! (contract-call? token transfer amount sender recipient memo))
        (ok true)
    )
)