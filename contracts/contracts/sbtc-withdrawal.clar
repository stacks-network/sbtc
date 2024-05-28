;; Error codes

(define-constant dust-limit u546)

;; The `version` part of the recipient address is invalid
(define-constant ERR_INVALID_ADDR_VERSION (err u500))
;; The `hashbytes` part of the recipient address is invalid
(define-constant ERR_INVALID_ADDR_HASHBYTES (err u501))
;; The size of the withdrawal is smaller than the dust limit
(define-constant ERR_DUST_LIMIT (err u502))

;; Maximum value of an address version as a uint
(define-constant MAX_ADDRESS_VERSION u6)
;; Maximum value of an address version that has a 20-byte hashbytes
;; (0x00, 0x01, 0x02, 0x03, and 0x04 have 20-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_20 u4)
;; Maximum value of an address version that has a 32-byte hashbytes
;; (0x05 and 0x06 have 32-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_32 u6)

(define-public (initiate-withdrawal-request (amount uint)
                                            (recipient { version: (buff 1), hashbytes: (buff 32) })
                                            (max-fee uint)
  )
  (begin
    (try! (contract-call? .sbtc-token protocol-lock amount tx-sender))
    (asserts! (> amount dust-limit) ERR_DUST_LIMIT)
  
    ;; Validate the recipient address
    (try! (validate-recipient recipient))
    
    (ok (try! (contract-call? .sbtc-registry create-withdrawal-request amount max-fee tx-sender recipient burn-block-height)))
  )
)

;; Validation methods

;; Validate that a withdrawal's recipient address is well-formed.
;; The logic here follows the same rules as pox-4.
;; 
;; At a high-level, the version must be a uint between 0 and 6 (inclusive),
;; and the length of the hashbytes must be 20 bytes if the version is <= 4,
;; and 32 bytes if the version is 5 or 6.
(define-read-only (validate-recipient (recipient { version: (buff 1), hashbytes: (buff 32) }))
  (let
    (
      (version (get version recipient))
      (hashbytes (get hashbytes recipient))
      (version-int (buff-to-uint-be version))
    )
    ;; Validate the `version`
    (asserts! (<= version-int MAX_ADDRESS_VERSION) ERR_INVALID_ADDR_VERSION)
    ;; Validate the length of `hashbytes`
    (asserts! (if (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION_BUFF_20)
        ;; If version is <= 4, then hashbytes must be 20 bytes
        (is-eq (len hashbytes) u20)
        ;; Otherwise, hashbytes must be 32 bytes
        (is-eq (len hashbytes) u32))
      ERR_INVALID_ADDR_HASHBYTES)
    (ok true)
  )
)