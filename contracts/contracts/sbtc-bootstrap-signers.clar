;; sBTC Bootstrap Signers contract

;; constants
(define-constant signature-threshold u8)
(define-constant key-size u32)

;; errors
(define-constant ERR_KEY_SIZE_PREFIX u200)
(define-constant ERR_KEY_SIZE (err u200))

;; data vars
;;

;; data maps
;;

;; public functions
;; Rotate keys
;; Used to rotate the keys of the signers. This is called whenever
;; the signer set is updated.
(define-public (rotate-keys-wrapper (new-keys (list 15 (buff 32))) (new-address principal) (new-aggregate-pubkey (buff 32)))
    (let 
        (
            (current-signer-data (contract-call? .sbtc-registry get-current-signer-data))   
        )
        ;; TODO: check that tx-sender, using principal-construct? is a current signer

        ;; Checks that length of each key is exactly 32 bytes
        (try! (fold signer-key-length-check new-keys (ok {index: u0})))

        ;; Check that length of new-aggregate-pubkey is exactly 32 bytes
        (asserts! (is-eq (len new-aggregate-pubkey) key-size) ERR_KEY_SIZE)

        ;; Call into .sbtc-registry to update the keys & address
        (ok true)
    )
)

;; read only functions
;;

;; private functions
;; Signer Key Length Check
;; Checks that the length of each key is exactly 32 bytes
(define-private (signer-key-length-check (current-key (buff 32)) (helper-response (response {index: uint} uint)))
    (match helper-response
        ok-response
            (begin 
                (asserts! (is-eq (len current-key) key-size) (err (+ ERR_KEY_SIZE_PREFIX (get index ok-response))))
                (ok {index: (+ (get index ok-response) u1)})
            )
        err-response
            (err err-response)
    )
)

