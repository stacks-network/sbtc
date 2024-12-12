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

(define-public (call-all-token-protocol-functions)
	(let ((total-supply (contract-call? .sbtc-token get-total-supply)))
		(try! (contract-call? .sbtc-token protocol-mint u90 tx-sender 0x03))
		(try! (contract-call? .sbtc-token protocol-mint-many (list {amount: u10, recipient: tx-sender} {amount: u10, recipient: (as-contract tx-sender)}) 0x03))
		(asserts! (is-eq (contract-call? .sbtc-token get-total-supply) (ok (+ (unwrap-panic total-supply) u110))) (err u99))
		(try! (contract-call? .sbtc-token protocol-lock u50 tx-sender 0x03))
		(try! (contract-call? .sbtc-token protocol-unlock u40 tx-sender 0x03))
		(try! (contract-call? .sbtc-token protocol-burn u20 tx-sender 0x03))
		(try! (contract-call? .sbtc-token protocol-burn u10 (as-contract tx-sender) 0x03))
		(asserts! (is-eq (contract-call? .sbtc-token get-total-supply) (ok (+ (unwrap-panic total-supply) u80))) (err u99))
		(try! (contract-call? .sbtc-token protocol-burn-locked u5 tx-sender 0x03))
		(asserts! (is-eq (contract-call? .sbtc-token get-total-supply) (ok (+ (unwrap-panic total-supply) u75))) (err u99))
		(try! (contract-call? .sbtc-token protocol-set-name "sbtc-2" 0x03))
		(try! (contract-call? .sbtc-token protocol-set-symbol "SBTC2" 0x03))
		(try! (contract-call? .sbtc-token protocol-set-token-uri none 0x03))
		(ok (list
			(contract-call? .sbtc-token get-balance tx-sender)
			(contract-call? .sbtc-token get-balance-available tx-sender)
			(contract-call? .sbtc-token get-balance-locked tx-sender)))
	)
)