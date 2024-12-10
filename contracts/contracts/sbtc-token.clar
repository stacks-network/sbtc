(define-constant ERR_NOT_OWNER (err u4)) ;; `tx-sender` or `contract-caller` tried to move a token it does not own.
(define-constant ERR_NOT_AUTH (err u5)) ;; `tx-sender` or `contract-caller` is not the protocol caller
(define-constant ERR_TRANSFER_INDEX_PREFIX (unwrap-err! ERR_TRANSFER (err true)))
(define-constant ERR_TRANSFER (err u6))

(define-fungible-token sbtc-token)
(define-fungible-token sbtc-token-locked)

(define-data-var token-name (string-ascii 32) "sBTC")
(define-data-var token-symbol (string-ascii 10) "sBTC")
(define-data-var token-uri (optional (string-utf8 256)) none)
(define-constant token-decimals u8)

;; --- Protocol functions

;; #[allow(unchecked_data)]
(define-public (protocol-transfer (amount uint) (sender principal) (recipient principal))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ft-transfer? sbtc-token amount sender recipient)
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-lock (amount uint) (owner principal))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(try! (ft-burn? sbtc-token amount owner))
		(ft-mint? sbtc-token-locked amount owner)
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-unlock (amount uint) (owner principal))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(try! (ft-burn? sbtc-token-locked amount owner))
		(ft-mint? sbtc-token amount owner)
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-mint (amount uint) (recipient principal))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ft-mint? sbtc-token amount recipient)
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-burn (amount uint) (owner principal))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ft-burn? sbtc-token amount owner)
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-burn-locked (amount uint) (owner principal))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ft-burn? sbtc-token-locked amount owner)
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-set-name (new-name (string-ascii 32)))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ok (var-set token-name new-name))
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-set-symbol (new-symbol (string-ascii 10)))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ok (var-set token-symbol new-symbol))
	)
)

;; #[allow(unchecked_data)]
(define-public (protocol-set-token-uri (new-uri (optional (string-utf8 256))))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ok (var-set token-uri new-uri))
	)
)

;; #[allow(unchecked_data)]
(define-private (protocol-mint-many-iter (item {amount: uint, recipient: principal}))
	(ft-mint? sbtc-token (get amount item) (get recipient item))
)

;; #[allow(unchecked_data)]
(define-public (protocol-mint-many (recipients (list 200 {amount: uint, recipient: principal})))
	(begin
		(try! (contract-call? .sbtc-registry validate-protocol-caller contract-caller))
		(ok (map protocol-mint-many-iter recipients))
	)
)

;; --- Public functions
(define-public (transfer-many 
				(recipients (list 200 { 
					amount: uint, 
					sender: principal, 
					to: principal, 
					memo: (optional (buff 34)) })))
	(fold complete-individual-transfer recipients (ok u0))
)

(define-private (complete-individual-transfer 
					(individual-transfer { 
						amount: uint, 
						sender: principal, 
						to: principal, 
						memo: (optional (buff 34)) }) 
					(helper-response (response uint uint)))
    (match helper-response 
        index
            (begin 
                (unwrap! 
					(transfer 
						(get amount individual-transfer) 
						(get sender individual-transfer) 
						(get to individual-transfer) 
						(get memo individual-transfer)) 
				(err (+ ERR_TRANSFER_INDEX_PREFIX index)))
                (ok (+ index u1))
            )
        err-response
            (err err-response)
    )
)

;; sip-010-trait

;; #[allow(unchecked_data)]
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
	(begin
		(asserts! (or (is-eq tx-sender sender) (is-eq contract-caller sender)) ERR_NOT_OWNER)
		(try! (ft-transfer? sbtc-token amount sender recipient))
		(match memo to-print (print to-print) 0x)
		(ok true)
	)
)

(define-read-only (get-name)
	(ok (var-get token-name))
)

(define-read-only (get-symbol)
	(ok (var-get token-symbol))
)

(define-read-only (get-decimals)
	(ok token-decimals)
)

(define-read-only (get-balance (who principal))
	(ok (+ (ft-get-balance sbtc-token who) (ft-get-balance sbtc-token-locked who)))
)

(define-read-only (get-balance-available (who principal))
	(ok (ft-get-balance sbtc-token who))
)

(define-read-only (get-balance-locked (who principal))
	(ok (ft-get-balance sbtc-token-locked who))
)

(define-read-only (get-total-supply)
	(ok (+ (ft-get-supply sbtc-token) (ft-get-supply sbtc-token-locked)))
)

(define-read-only (get-token-uri)
	(ok (var-get token-uri))
)