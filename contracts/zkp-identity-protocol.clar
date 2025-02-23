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


(define-public (revoke-identity
    (identity-hash (buff 32)))
    (let
        ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) ERR-NO-IDENTITY))
         (sender tx-sender))

        ;; Verify ownership
        (asserts! (or 
            (is-eq sender (get owner identity))
            (is-eq sender CONTRACT-OWNER)) ERR-UNAUTHORIZED)

        ;; Update identity status
        (map-set Identities
            { identity-hash: identity-hash }
            (merge identity {
                status: STATUS-REVOKED,
                revocation-height: (some stacks-block-height)
            }))

        (ok true)))

;; Verifier Management
(define-public (register-verifier
    (verifier principal)
    (allowed-types (list 10 uint)))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)

        (map-set Verifiers
            { verifier: verifier }
            {
                allowed-types: allowed-types,
                verifications-performed: u0,
                last-verification: u0,
                is-active: true
            })
        (ok true)))

;; Read-only functions
(define-read-only (get-identity-info (identity-hash (buff 32)))
    (map-get? Identities {identity-hash: identity-hash}))

(define-read-only (get-proof-info (proof-hash (buff 32)))
    (map-get? ProofRegistry {proof-hash: proof-hash}))

(define-read-only (get-verifier-info (verifier principal))
    (map-get? Verifiers {verifier: verifier}))

(define-read-only (is-identity-valid
    (identity-hash (buff 32))
    (verification-type uint))
    (let ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) false)))
        (and
            (is-eq (get status identity) STATUS-ACTIVE)
            (< stacks-block-height (get expiry-height identity))
            (is-some (index-of (get verification-types identity) verification-type)))))



;; Data map for verification history
(define-map VerificationHistory
    { identity-hash: (buff 32) }
    {
        total-verifications: uint,
        last-verification-height: uint,
        type1-count: uint,
        type2-count: uint,
        type3-count: uint,
        type4-count: uint,
        last-verifier: (optional principal)
    }
)

;; Update verification history after successful verification
(define-private (update-verification-history 
    (identity-hash (buff 32))
    (verification-type uint))
    (let
        ((current-history (default-to
            {
                total-verifications: u0,
                last-verification-height: u0,
                type1-count: u0,
                type2-count: u0,
                type3-count: u0,
                type4-count: u0,
                last-verifier: none
            }
            (map-get? VerificationHistory { identity-hash: identity-hash })))
         (updated-type-count 
            (if (is-eq verification-type TYPE-KYC)
                (+ (get type1-count current-history) u1)
                (if (is-eq verification-type TYPE-AGE)
                    (+ (get type2-count current-history) u1)
                    (if (is-eq verification-type TYPE-LOCATION)
                        (+ (get type3-count current-history) u1)
                        (if (is-eq verification-type TYPE-ACCREDITED)
                            (+ (get type4-count current-history) u1)
                            u0))))))

        ;; Update the history with new counts
        (map-set VerificationHistory
            { identity-hash: identity-hash }
            {
                total-verifications: (+ (get total-verifications current-history) u1),
                last-verification-height: stacks-block-height,
                type1-count: (if (is-eq verification-type TYPE-KYC) 
                               updated-type-count 
                               (get type1-count current-history)),
                type2-count: (if (is-eq verification-type TYPE-AGE) 
                               updated-type-count 
                               (get type2-count current-history)),
                type3-count: (if (is-eq verification-type TYPE-LOCATION) 
                               updated-type-count 
                               (get type3-count current-history)),
                type4-count: (if (is-eq verification-type TYPE-ACCREDITED) 
                               updated-type-count 
                               (get type4-count current-history)),
                last-verifier: (some tx-sender)
            })

        ;; Return specific error types to match public function
        (if (is-eq verification-type u0)
            ERR-INVALID-PROOF
            (ok true))))


;; Function 1: Update verification types for an identity
(define-public (update-verification-types
    (identity-hash (buff 32))
    (new-verification-types (list 10 uint)))
    (let
        ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) ERR-NO-IDENTITY))
         (sender tx-sender))

        ;; Verify ownership
        (asserts! (is-eq (get owner identity) sender) ERR-UNAUTHORIZED)
        (asserts! (is-eq (get status identity) STATUS-ACTIVE) ERR-REVOKED)
        (asserts! (< stacks-block-height (get expiry-height identity)) ERR-EXPIRED)

        ;; Update verification types
        (map-set Identities
            { identity-hash: identity-hash }
            (merge identity {
                verification-types: new-verification-types
            }))

        (ok true)))

;; Function 2: Extend identity expiry
(define-public (extend-identity-expiry
    (identity-hash (buff 32))
    (additional-blocks uint))
    (let
        ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) ERR-NO-IDENTITY))
         (sender tx-sender))

        ;; Verify ownership and status
        (asserts! (is-eq (get owner identity) sender) ERR-UNAUTHORIZED)
        (asserts! (is-eq (get status identity) STATUS-ACTIVE) ERR-REVOKED)

        ;; Update expiry
        (map-set Identities
            { identity-hash: identity-hash }
            (merge identity {
                expiry-height: (+ (get expiry-height identity) additional-blocks)
            }))

        (ok true)))



;; Read-only function to get verification history
(define-read-only (get-verification-history 
    (identity-hash (buff 32)))
    (map-get? VerificationHistory { identity-hash: identity-hash }))

;; Modified verify-proof-with-tracking to include history
(define-public (verify-proof-with-tracking
    (identity-hash (buff 32))
    (proof-hash (buff 32))
    (verification-type uint))
    (let
        ((identity (unwrap! (map-get? Identities {identity-hash: identity-hash}) ERR-NO-IDENTITY))
         (proof (unwrap! (map-get? ProofRegistry {proof-hash: proof-hash}) ERR-INVALID-PROOF))
         (verifier (unwrap! (map-get? Verifiers {verifier: tx-sender}) ERR-UNAUTHORIZED)))

        ;; Verify proof validity
        (asserts! (get is-valid proof) ERR-VERIFICATION-FAILED)
        (asserts! (< stacks-block-height (get expiry-height proof)) ERR-EXPIRED)
        (asserts! (is-eq (get verification-type proof) verification-type) ERR-INVALID-PROOF)

        ;; Verify verifier authorization
        (asserts! (get is-active verifier) ERR-UNAUTHORIZED)
        (asserts! (is-some (index-of (get allowed-types verifier) verification-type)) ERR-INVALID-VERIFIER)

        ;; Update verification history - handle potential errors
        (try! (update-verification-history identity-hash verification-type))

        ;; Track verification in contract
        (map-set Verifiers
            { verifier: tx-sender }
            (merge verifier {
                verifications-performed: (+ (get verifications-performed verifier) u1),
                last-verification: stacks-block-height
            }))

        (ok true)))

;; Get verification count for specific type
(define-read-only (get-verification-count-by-type
    (identity-hash (buff 32))
    (verification-type uint))
    (let
        ((history (unwrap! (map-get? VerificationHistory { identity-hash: identity-hash }) ERR-NO-IDENTITY)))

        (ok (if (is-eq verification-type TYPE-KYC)
            (get type1-count history)
            (if (is-eq verification-type TYPE-AGE)
                (get type2-count history)
                (if (is-eq verification-type TYPE-LOCATION)
                    (get type3-count history)
                    (if (is-eq verification-type TYPE-ACCREDITED)
                        (get type4-count history)
                        u0)))))))