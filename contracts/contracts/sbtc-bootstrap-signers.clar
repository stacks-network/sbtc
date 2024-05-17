;; sBTC Bootstrap Signers contract

;; constants
(define-constant signature-threshold u8)
(define-constant key-size u32)

;; errors
;; if err is u200, it's the agg key
;; if err is u210>, it's the key at index (err - 210)
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
;; TODO - construct multi-sig address from keys
(define-public (rotate-keys-wrapper (new-keys (list 15 (buff 32))) (multi-sig-address principal) (new-aggregate-pubkey (buff 32)))
    (let 
        (
            (current-signer-data (contract-call? .sbtc-registry get-current-signer-data))   
        )
        ;; TODO: check that tx-sender, using principal-construct? is a current signer
        ;; Check that tx-sender is a multi-sig address

        ;; Checks that length of each key is exactly 32 bytes
        (try! (fold signer-key-length-check new-keys (ok u0)))

        ;; Check that length of new-aggregate-pubkey is exactly 32 bytes
        (asserts! (is-eq (len new-aggregate-pubkey) key-size) ERR_KEY_SIZE)

        ;; Call into .sbtc-registry to update the keys & address
        (ok (try! (contract-call? .sbtc-registry rotate-keys new-keys multi-sig-address new-aggregate-pubkey)))
    )
)

;; read only functions
;;

;; private functions
;; Signer Key Length Check
;; Checks that the length of each key is exactly 32 bytes
(define-private (signer-key-length-check (current-key (buff 32)) (helper-response (response uint uint)))
    (match helper-response
        index
            (begin 
                (asserts! (is-eq (len current-key) key-size) (err (+ ERR_KEY_SIZE_PREFIX (+ u10 index))))
                (ok (+ index u1))
            )
        err-response
            (err err-response)
    )
)

