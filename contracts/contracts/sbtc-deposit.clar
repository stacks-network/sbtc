;; sBTC Deposit contract

;; constants

;; The required length of a txid
(define-constant txid-length u32)
(define-constant dust-limit u546)

;; error codes

;; TXID used in deposit is not the correct length
(define-constant ERR_TXID_LEN (err u300))
;; Deposit has already been completed
(define-constant ERR_DEPOSIT_REPLAY (err u301))
(define-constant ERR_LOWER_THAN_DUST (err u302))

;; data vars

;; data maps

;; public functions

;; Accept a new deposit request
;; Note that this function can only be called by the current
;; bootstrap signer set address - it cannot be called by users directly.
;; This function handles the validation & minting of sBTC, it then calls
;; into the sbtc-registry contract to update the state of the protocol
(define-public (complete-deposit-wrapper (txid (buff 32)) (vout-index uint) (amount uint) (recipient principal))
    (let 
        (
            (replay-fetch (contract-call? .sbtc-registry get-completed-deposit txid vout-index))    
        )

        ;; TODO
        ;; Check that tx-sender is the bootstrap signer

        ;; Check that amount is greater than dust limit
        (asserts! (> amount dust-limit) ERR_LOWER_THAN_DUST)

        ;; Check that txid is the correct length
        (asserts! (is-eq (len txid) txid-length) ERR_TXID_LEN)

        ;; Assert that the deposit has not already been completed (no replay)
        (asserts! (is-none replay-fetch) ERR_DEPOSIT_REPLAY)

        ;; Mint the sBTC to the recipient
        (try! (contract-call? .sbtc-token protocol-mint amount recipient))

        ;; Complete the deposit
        (ok (contract-call? .sbtc-registry complete-deposit txid vout-index amount recipient))
    )
)

;; Accept multiple new deposit requests
;; Note that this function can only be called by the current
;; bootstrap signer set address - it cannot be called by users directly.
;; 
;; This function handles the validation & minting of sBTC by handling multiple (up to 1000) deposits at a time, 
;; it then calls into the sbtc-registry contract to update the state of the protocol

;; read only functions
;;

;; private functions
;;

