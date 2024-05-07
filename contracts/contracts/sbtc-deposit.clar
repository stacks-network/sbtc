;; sBTC Deposit contract

;; constants
(define-constant txid-length u32)

;; error codes
(define-constant ERR_TXID_LEN u300)

;; data vars
;;

;; data maps
;;

;; public functions

;; Accept a new deposit request
;; Note that this function can only be called by the current
;; bootstrap signer set address - it cannot be called by users directly.
;; 
;; This function handles the validation & minting of sBTC, it then calls
;; into the sbtc-registry contract to update the state of the protocol
(define-public (complete-deposit-wrapper (txid (buff 32)) (vout-index uint) (amount uint) (recipient principal))
    ;; TODO
    ;; implement, placeholder for completing deposit contract setup
    (contract-call? .sbtc-registry complete-deposit txid vout-index amount recipient)
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

