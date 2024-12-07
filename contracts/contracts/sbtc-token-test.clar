;; send many sbtc tokens
(define-public (send-many-sbtc-tokens (recipients (list 10 principal)))
    (as-contract (contract-call? .sbtc-token transfer-many (list
        {
            amount: u100,
            sender: tx-sender,
            to: (unwrap-panic (element-at? recipients u0)),
            memo: none
        }
        {
            amount: u100,
            sender: tx-sender,
            to: (unwrap-panic (element-at? recipients u1)),
            memo: none
        }
        {
            amount: u100,
            sender: tx-sender,
            to: (unwrap-panic (element-at? recipients u2)),
            memo: none
        })))
)