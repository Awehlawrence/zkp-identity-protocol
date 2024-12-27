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
