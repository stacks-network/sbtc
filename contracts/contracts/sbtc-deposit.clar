;; sBTC Deposit contract

;; constants

;; The required length of a txid
(define-constant txid-length u32)
(define-constant dust-limit u546)

;; protocol contract type
(define-constant deposit-role 0x01)

;; error codes
;; TXID used in deposit is not the correct length
(define-constant ERR_TXID_LEN (err u300))
;; Deposit has already been completed
(define-constant ERR_DEPOSIT_REPLAY (err u301))
(define-constant ERR_LOWER_THAN_DUST (err u302))
(define-constant ERR_DEPOSIT_INDEX_PREFIX (unwrap-err! ERR_DEPOSIT (err true)))
(define-constant ERR_DEPOSIT (err u303))
(define-constant ERR_INVALID_CALLER (err u304))
(define-constant ERR_INVALID_BURN_HASH (err u305))

;; public functions

;; Accept a new deposit request
;; Note that this function can only be called by the current
;; bootstrap signer set address - it cannot be called by users directly.
;; This function handles the validation & minting of sBTC, it then calls
;; into the sbtc-registry contract to update the state of the protocol
(define-public (complete-deposit-wrapper (txid (buff 32))
										 (vout-index uint)
										 (amount uint)
										 (recipient principal)
										 (burn-hash (buff 32))
										 (burn-height uint)
										 (sweep-txid (buff 32)))
	(let
		(
			(current-signer-data (contract-call? .sbtc-registry get-current-signer-data))
			(replay-fetch (contract-call? .sbtc-registry get-deposit-status txid vout-index))
		)

		;; Check that the caller is the current signer principal
		(asserts! (is-eq (get current-signer-principal current-signer-data) tx-sender) ERR_INVALID_CALLER)

		;; Check that amount is greater than dust limit
		(asserts! (>= amount dust-limit) ERR_LOWER_THAN_DUST)

		;; Check that txid is the correct length
		(asserts! (is-eq (len txid) txid-length) ERR_TXID_LEN)

		;; Check that sweep txid is the correct length
		(asserts! (is-eq (len sweep-txid) txid-length) ERR_TXID_LEN)

		;; Assert that the deposit has not already been completed (no replay)
		(asserts! (is-none replay-fetch) ERR_DEPOSIT_REPLAY)

		;; Verify that Bitcoin hasn't forked by comparing the burn hash provided
		(asserts! (is-eq (some burn-hash) (get-burn-header burn-height)) ERR_INVALID_BURN_HASH)

		;; Mint the sBTC to the recipient
		(try! (contract-call? .sbtc-token protocol-mint amount recipient deposit-role))

		;; Complete the deposit
		(contract-call? .sbtc-registry complete-deposit txid vout-index amount recipient burn-hash burn-height sweep-txid)
	)
)

;; Return the bitcoin header hash of the bitcoin block at the given height.
(define-read-only (get-burn-header (height uint))
	(get-burn-block-info? header-hash height)
)

;; Accept multiple new deposit requests
;; Note that this function can only be called by the current
;; bootstrap signer set address - it cannot be called by users directly.
;;
;; This function handles the validation & minting of sBTC by handling multiple (up to 500) deposits at a time,
;; it then calls into the sbtc-registry contract to update the state of the protocol.
(define-public (complete-deposits-wrapper
		(deposits (list 500 {txid: (buff 32), vout-index: uint, amount: uint, recipient: principal, burn-hash: (buff 32), burn-height: uint, sweep-txid: (buff 32)}))
	)
	(begin
		;; Check that the caller is the current signer principal
		(asserts! (is-eq
			(contract-call? .sbtc-registry get-current-signer-principal)
			tx-sender
		) ERR_INVALID_CALLER)

		(fold complete-individual-deposits-helper deposits (ok u0))
	)
)

;; private functions
(define-private (complete-individual-deposits-helper (deposit {txid: (buff 32), vout-index: uint, amount: uint, recipient: principal, burn-hash: (buff 32), burn-height: uint, sweep-txid: (buff 32)}) (helper-response (response uint uint)))
	(match helper-response
		index
			(begin
				(unwrap!
					(complete-deposit-wrapper
						(get txid deposit)
						(get vout-index deposit)
						(get amount deposit)
						(get recipient deposit)
						(get burn-hash deposit)
						(get burn-height deposit)
						(get sweep-txid deposit))
				(err (+ ERR_DEPOSIT_INDEX_PREFIX (+ u10 index))))
				(ok (+ index u1))
			)
		err-response
			(err err-response)
	)
)

