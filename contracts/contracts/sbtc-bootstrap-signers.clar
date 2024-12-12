;; sBTC Bootstrap Signers contract

;; constants
;; The required length of public keys
(define-constant key-size u33)

;; if err is u200, it's the agg key
;; if err is u210>, it's the key at index (err - 210)
(define-constant ERR_KEY_SIZE_PREFIX (unwrap-err! ERR_KEY_SIZE (err true)))
(define-constant ERR_KEY_SIZE (err u200))
;; The function caller is not the current signer principal
(define-constant ERR_INVALID_CALLER (err u201))
;; The given signature threshold must be greater than 50% and less than or
;; equal to 100% of the total number of signer keys.
(define-constant ERR_SIGNATURE_THRESHOLD (err u202))

;; Rotate keys
;; Used to rotate the keys of the signers. This is called whenever
;; the signer set is updated.
(define-public (rotate-keys-wrapper
	(new-keys (list 128 (buff 33)))
		(new-aggregate-pubkey (buff 33))
		(new-signature-threshold uint)
	)
		(let
			(
				(new-signer-principal (pubkeys-to-principal new-keys new-signature-threshold))
			)

			;; Check that more than 1 key is in the new set
			(asserts! (> (len new-keys) u1) ERR_KEY_SIZE)

			;; Check that the signature threshold is valid
			(asserts! (and (> new-signature-threshold (/ (len new-keys) u2))
											(<= new-signature-threshold (len new-keys))) ERR_SIGNATURE_THRESHOLD)

			;; Check that the tx-sender is the current signer principal
			(asserts! (is-eq (contract-call? .sbtc-registry get-current-signer-principal) tx-sender) ERR_INVALID_CALLER)

			;; Checks that length of each key is exactly 33 bytes
			(try! (fold signer-key-length-check new-keys (ok u0)))

			;; Check that length of new-aggregate-pubkey is exactly 33 bytes
			(asserts! (is-eq (len new-aggregate-pubkey) key-size) ERR_KEY_SIZE)

			;; Call into .sbtc-registry to update the keys & address
			(contract-call? .sbtc-registry rotate-keys new-keys new-signer-principal new-aggregate-pubkey new-signature-threshold)
		)
)

;; Update protocol contract
;; Used to update one of the three protocol contracts
(define-public (update-protocol-contract-wrapper (contract-type (buff 1)) (contract-address principal))
	(begin
		;; Check that the tx-sender is the current signer principal
		(asserts! (is-eq (contract-call? .sbtc-registry get-current-signer-principal) tx-sender) ERR_INVALID_CALLER)
		;; Call into .sbtc-registry to update the protocol contract
		(contract-call? .sbtc-registry update-protocol-contract contract-type contract-address)
	)
)

;; read only functions

;; Signer Key Length Check
;; Checks that the length of each key is exactly 33 bytes
(define-private (signer-key-length-check (current-key (buff 33)) (helper-response (response uint uint)))
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

;; Multisig generation

;; Generate the p2sh redeem script for a multisig
(define-read-only (pubkeys-to-spend-script
		(pubkeys (list 128 (buff 33)))
		(m uint)
	)
	(concat (uint-to-byte (+ u80 m)) ;; "m" in m-of-n
	(concat (pubkeys-to-bytes pubkeys) ;; list of pubkeys with length prefix
	(concat (uint-to-byte (+ u80 (len pubkeys))) ;; "n" in m-of-n
	0xae ;; CHECKMULTISIG
	)))
)

;; hash160 of the p2sh redeem script
(define-read-only (pubkeys-to-hash
		(pubkeys (list 128 (buff 33)))
		(m uint)
	)
	(hash160 (pubkeys-to-spend-script pubkeys m))
)

;; Given a set of pubkeys and an m-of-n, generate a principal
(define-read-only (pubkeys-to-principal
		(pubkeys (list 128 (buff 33)))
		(m uint)
	)
	(unwrap-panic (principal-construct?
		(if is-in-mainnet 0x14 0x15) ;; address version
		(pubkeys-to-hash pubkeys m)
	))
)

;; Concat a list of pubkeys into a buffer with length prefixes
(define-read-only (pubkeys-to-bytes (pubkeys (list 128 (buff 33))))
	(fold concat-pubkeys-fold pubkeys 0x)
)

;; Concatenate a pubkey buffer with a length prefix.
;; The max size of the iterator is 4352 bytes, which is (33 * 128) 4224 bytes
;; for the public keys and 128 bytes for the length prefixes.
(define-read-only (concat-pubkeys-fold (pubkey (buff 33)) (iterator (buff 4352)))
	(let
		(
			(pubkey-with-len (concat (bytes-len pubkey) pubkey))
			(next (concat iterator pubkey-with-len))
		)
		(unwrap-panic (as-max-len? next u4352))
	)
)

(define-read-only (bytes-len (bytes (buff 33)))
	(unwrap-panic (element-at BUFF_TO_BYTE (len bytes)))
)

(define-read-only (uint-to-byte (n uint))
	(unwrap-panic (element-at BUFF_TO_BYTE n))
)

(define-constant BUFF_TO_BYTE (list
	0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
	0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f
	0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28 0x29 0x2a 0x2b 0x2c 0x2d 0x2e 0x2f
	0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x39 0x3a 0x3b 0x3c 0x3d 0x3e 0x3f
	0x40 0x41 0x42 0x43 0x44 0x45 0x46 0x47 0x48 0x49 0x4a 0x4b 0x4c 0x4d 0x4e 0x4f
	0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x59 0x5a 0x5b 0x5c 0x5d 0x5e 0x5f
	0x60 0x61 0x62 0x63 0x64 0x65 0x66 0x67 0x68 0x69 0x6a 0x6b 0x6c 0x6d 0x6e 0x6f
	0x70 0x71 0x72 0x73 0x74 0x75 0x76 0x77 0x78 0x79 0x7a 0x7b 0x7c 0x7d 0x7e 0x7f
	0x80 0x81 0x82 0x83 0x84 0x85 0x86 0x87 0x88 0x89 0x8a 0x8b 0x8c 0x8d 0x8e 0x8f
	0x90 0x91 0x92 0x93 0x94 0x95 0x96 0x97 0x98 0x99 0x9a 0x9b 0x9c 0x9d 0x9e 0x9f
	0xa0 0xa1 0xa2 0xa3 0xa4 0xa5 0xa6 0xa7 0xa8 0xa9 0xaa 0xab 0xac 0xad 0xae 0xaf
	0xb0 0xb1 0xb2 0xb3 0xb4 0xb5 0xb6 0xb7 0xb8 0xb9 0xba 0xbb 0xbc 0xbd 0xbe 0xbf
	0xc0 0xc1 0xc2 0xc3 0xc4 0xc5 0xc6 0xc7 0xc8 0xc9 0xca 0xcb 0xcc 0xcd 0xce 0xcf
	0xd0 0xd1 0xd2 0xd3 0xd4 0xd5 0xd6 0xd7 0xd8 0xd9 0xda 0xdb 0xdc 0xdd 0xde 0xdf
	0xe0 0xe1 0xe2 0xe3 0xe4 0xe5 0xe6 0xe7 0xe8 0xe9 0xea 0xeb 0xec 0xed 0xee 0xef
	0xf0 0xf1 0xf2 0xf3 0xf4 0xf5 0xf6 0xf7 0xf8 0xf9 0xfa 0xfb 0xfc 0xfd 0xfe 0xff
))
