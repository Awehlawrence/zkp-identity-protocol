;; ZKP Identity Protocol
;; Implements privacy-preserving identity verification

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u1))
(define-constant ERR-INVALID-PROOF (err u2))
(define-constant ERR-IDENTITY-EXISTS (err u3))
(define-constant ERR-NO-IDENTITY (err u4))
(define-constant ERR-EXPIRED (err u5))
(define-constant ERR-INVALID-VERIFIER (err u6))
(define-constant ERR-REVOKED (err u7))
(define-constant ERR-VERIFICATION-FAILED (err u8))

;; Identity Status
(define-constant STATUS-ACTIVE u1)
(define-constant STATUS-REVOKED u2)
(define-constant STATUS-EXPIRED u3)

;; Verification Types
(define-constant TYPE-KYC u1)
(define-constant TYPE-AGE u2)
(define-constant TYPE-LOCATION u3)
(define-constant TYPE-ACCREDITED u4)

;; Data Maps
(define-map Identities
    { identity-hash: (buff 32) }
    {
        owner: principal,
        status: uint,
        creation-height: uint,
        expiry-height: uint,
        verification-types: (list 10 uint),
        merkle-root: (buff 32),
        attestations: uint,
        revocation-height: (optional uint)
    }
)

(define-map Verifiers
    { verifier: principal }
    {
        allowed-types: (list 10 uint),
        verifications-performed: uint,
        last-verification: uint,
        is-active: bool
    }
)

(define-map VerificationRequests
    { request-id: uint }
    {
        requester: principal,
        identity-hash: (buff 32),
        verification-type: uint,
        request-height: uint,
        status: uint,
        proof: (optional (buff 512)),
        verifier: (optional principal)
    }
)

(define-map ProofRegistry
    { proof-hash: (buff 32) }
    {
        identity-hash: (buff 32),
        verification-type: uint,
        creation-height: uint,
        expiry-height: uint,
        is-valid: bool
    }
)

;; Variables
(define-data-var next-request-id uint u0)
(define-data-var total-identities uint u0)
(define-data-var total-verifications uint u0)

;; Private Functions
(define-private (hash-identity-data 
    (data (buff 512))
    (salt (buff 32)))
    (sha256 (concat data salt)))

(define-private (verify-merkle-proof
    (proof (buff 512))
    (root (buff 32))
    (leaf (buff 32)))
    (is-eq root (sha256 (concat leaf proof))))


;; Identity Management Functions
(define-public (register-identity
    (identity-hash (buff 32))
    (merkle-root (buff 32))
    (verification-types (list 10 uint))
    (expiry-blocks uint))
    (let
        ((sender tx-sender))

        ;; Validate registration
        (asserts! (is-none (map-get? Identities {identity-hash: identity-hash})) ERR-IDENTITY-EXISTS)

        ;; Create identity record
        (map-set Identities
            { identity-hash: identity-hash }
            {
                owner: sender,
                status: STATUS-ACTIVE,
                creation-height: stacks-block-height,
                expiry-height: (+ stacks-block-height expiry-blocks),
                verification-types: verification-types,
                merkle-root: merkle-root,
                attestations: u0,
                revocation-height: none
            })

        (var-set total-identities (+ (var-get total-identities) u1))
        (ok true)))

(define-public (add-proof
    (identity-hash (buff 32))
    (proof (buff 512))
    (verification-type uint))
    (let
        ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) ERR-NO-IDENTITY))
         (sender tx-sender)
         (proof-hash (sha256 proof)))

        ;; Verify ownership and status
        (asserts! (is-eq (get owner identity) sender) ERR-UNAUTHORIZED)
        (asserts! (is-eq (get status identity) STATUS-ACTIVE) ERR-REVOKED)
        (asserts! (< stacks-block-height (get expiry-height identity)) ERR-EXPIRED)

        ;; Register proof
        (map-set ProofRegistry
            { proof-hash: proof-hash }
            {
                identity-hash: identity-hash,
                verification-type: verification-type,
                creation-height: stacks-block-height,
                expiry-height: (get expiry-height identity),
                is-valid: true
            })

        (ok proof-hash)))

(define-public (verify-identity
    (identity-hash (buff 32))
    (proof-hash (buff 32))
    (verification-type uint))
    (let
        ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) ERR-NO-IDENTITY))
         (proof (unwrap! (map-get? ProofRegistry {proof-hash: proof-hash}) ERR-INVALID-PROOF))
         (verifier (unwrap! (map-get? Verifiers {verifier: tx-sender}) ERR-UNAUTHORIZED)))

        ;; Verify proof validity
        (asserts! (is-eq (get identity-hash proof) identity-hash) ERR-INVALID-PROOF)
        (asserts! (is-eq (get verification-type proof) verification-type) ERR-INVALID-PROOF)
        (asserts! (get is-valid proof) ERR-VERIFICATION-FAILED)
        (asserts! (< stacks-block-height (get expiry-height proof)) ERR-EXPIRED)

        ;; Verify verifier authorization
        (asserts! (get is-active verifier) ERR-UNAUTHORIZED)
        (asserts! (is-some (index-of (get allowed-types verifier) verification-type)) ERR-INVALID-VERIFIER)

        ;; Update verification stats
        (map-set Verifiers
            { verifier: tx-sender }
            (merge verifier {
                verifications-performed: (+ (get verifications-performed verifier) u1),
                last-verification: stacks-block-height
            }))

        (var-set total-verifications (+ (var-get total-verifications) u1))
        (ok true)))