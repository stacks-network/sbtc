;; sBTC Bootstrap Signers contract

;; constants
(define-constant signature-threshold u8)
(define-constant key-size u32)

;; errors
(define-constant ERR_KEY_SIZE_PREFIX u200)

;; data vars
;;

;; data maps
;;

;; public functions
;; Rotate keys
;; Used to rotate the keys of the signers. This is called whenever
;; the signer set is updated.
(define-public (rotate-keys (new-keys (list 15 (buff 32))))
    (begin
        ;; Checks that length of each key is exactly 32 bytes
        (try! (fold signer-key-length-check new-keys (ok {index: u0})))
        ;; Checks that tx-sender is in the list of existing signers
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

