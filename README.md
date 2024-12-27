# ZKP Identity Protocol

## Overview
The ZKP Identity Protocol is a smart contract designed to implement a privacy-preserving identity verification system. This protocol leverages Zero-Knowledge Proofs (ZKP) to ensure that identity verifications can occur without disclosing sensitive personal information. It includes robust mechanisms for registering identities, managing verifications, and revoking identities or proofs. The contract is built to be deployed on a blockchain platform supporting Clarity language (e.g., Stacks blockchain).

---

## Features

1. **Privacy-Preserving Identity Verification**: Ensures identity verification is performed securely without revealing unnecessary information.
2. **Flexible Identity Management**:
   - Register new identities.
   - Add proofs to existing identities.
   - Revoke identities when required.
3. **Verifier System**:
   - Allows authorized verifiers to perform specific types of verification.
   - Tracks verifier activity.
4. **Read-Only Functions**:
   - Query identity and proof details.
   - Check identity validity.
5. **Expiration and Revocation**:
   - Proofs and identities can have defined expiration periods.
   - Revocation mechanisms ensure control over invalidated identities.

---

## Data Structures

### Constants
- **Contract Roles and Errors**:
  - `CONTRACT-OWNER`: The deployer and administrator of the contract.
  - `ERR-UNAUTHORIZED`, `ERR-INVALID-PROOF`, etc.: Specific error codes for handling various failure scenarios.
- **Identity Status**:
  - `STATUS-ACTIVE`: Identity is valid and active.
  - `STATUS-REVOKED`: Identity has been revoked.
  - `STATUS-EXPIRED`: Identity is no longer valid due to expiration.
- **Verification Types**:
  - `TYPE-KYC`: Know Your Customer verification.
  - `TYPE-AGE`: Age verification.
  - `TYPE-LOCATION`: Location verification.
  - `TYPE-ACCREDITED`: Accredited individual verification.

### Maps
- **Identities**: Tracks registered identities with metadata including owner, status, expiry, and more.
- **Verifiers**: Manages authorized verifiers and their permissions.
- **VerificationRequests**: Stores details of verification requests.
- **ProofRegistry**: Logs and tracks registered proofs.

### Variables
- `next-request-id`: Tracks the ID for the next verification request.
- `total-identities`: Counts the total registered identities.
- `total-verifications`: Counts the total successful verifications.

---

## Functions

### Public Functions

#### Identity Management

1. **`register-identity`**
   - Registers a new identity with:
     - `identity-hash`: Unique identifier for the identity.
     - `merkle-root`: Merkle tree root for verifying identity-related data.
     - `verification-types`: List of verification types applicable.
     - `expiry-blocks`: Duration (in blocks) before the identity expires.
   - Returns `true` on successful registration.

2. **`add-proof`**
   - Adds a proof for a specific verification type.
   - Inputs:
     - `identity-hash`: The identity to which the proof belongs.
     - `proof`: Zero-Knowledge Proof.
     - `verification-type`: Type of verification the proof pertains to.
   - Returns the proof hash.

3. **`verify-identity`**
   - Verifies an identity using a proof.
   - Inputs:
     - `identity-hash`: Identity to be verified.
     - `proof-hash`: Hash of the proof used.
     - `verification-type`: Type of verification to perform.
   - Updates verifier statistics and returns `true` if successful.

4. **`revoke-identity`**
   - Revokes an identity, marking it as `STATUS-REVOKED`.
   - Can be executed by the identity owner or `CONTRACT-OWNER`.

#### Verifier Management

1. **`register-verifier`**
   - Registers a new verifier with authorized verification types.
   - Inputs:
     - `verifier`: Principal of the verifier.
     - `allowed-types`: List of verification types the verifier is authorized for.
   - Restricted to the `CONTRACT-OWNER`.

### Read-Only Functions

1. **`get-identity-info`**
   - Returns the metadata of a registered identity.

2. **`get-proof-info`**
   - Returns details of a registered proof.

3. **`get-verifier-info`**
   - Retrieves verifier metadata.

4. **`is-identity-valid`**
   - Checks if an identity is valid for a specific verification type.

---

## Security Considerations

1. **Ownership Verification**:
   - Functions that modify identity or proof data ensure the caller is authorized.
2. **Proof Validation**:
   - Merkle proofs and hashes are checked to maintain integrity.
3. **Expiration Management**:
   - Both identities and proofs automatically become invalid after their expiry block.
4. **Revoke Mechanism**:
   - Revocation ensures that compromised or outdated identities can no longer be used.

---

## Usage Guide

1. **Register an Identity**:
   - Call `register-identity` with required parameters to create a new identity.
2. **Add Proof**:
   - Use `add-proof` to associate a Zero-Knowledge Proof with an identity.
3. **Verify an Identity**:
   - Verifiers can call `verify-identity` to confirm identity details using a proof.
4. **Revoke Identity**:
   - Identities can be revoked using `revoke-identity` if necessary.
5. **Query Data**:
   - Use the read-only functions to retrieve identity, proof, or verifier details.

---

## Future Enhancements

1. **Integration with Off-Chain Systems**:
   - Enable external verifiers to interact with the protocol.
2. **Additional Verification Types**:
   - Support more granular and customizable verification criteria.
3. **Improved Proof Storage**:
   - Optimize storage and retrieval of proofs to reduce costs.

---