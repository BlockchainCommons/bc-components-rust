# bc-components Guidelines

## Project Overview

This crate provides a collection of useful cryptographic primitives and components for use in higher-level [Blockchain Commons](https://blockchaincommons.com) projects. All the types are CBOR serializable, and many can also be serialized to and from URs (Uniform Resources).

## Development Environment

### Build/Test Commands

```bash
# Build the crate
cargo build

# Run tests
cargo test
cargo test --test <test_name>
cargo test --doc

# Check code quality
cargo clippy -- -D warnings

# Build documentation
cargo doc --no-deps --target-dir cargo-docs
```

### Development Guidelines

- **Production quality** - Write code as you would for a real-world implementation
- **Proper error handling** - Use `Result<T>` with `anyhow::Context` for all functions that can fail
- **Clean code** - Fix all compiler errors and Clippy lints
- **Security focus** - Cryptographic primitives must adhere to best practices and be thoroughly tested

### Testing

- Don't mark tasks as complete until all tests pass
- Security-critical components require comprehensive test coverage

## Important Dependencies

### `bc-research` Repository

Many of the types in this crate are implementations of specifications in the `bc-research` repository that is linked to this workspace. Always look for more detailed specifications in that repository.

### `dcbor` Repository

This repository relies heavily on the public API of the `dcbor` crate, which is in this workspace. You can research the actual code there or examine its cargo documentation in `dcbor/cargo-docs`.

### `bc-ur` Repository

The `bc-ur` crate is also in this workspace and provides the UR serialization/deserialization functionality. You can research the actual code there.

## Core `bc-components` Types and Concepts

### Key Data Types

| Type              | Description                                               |
| ----------------- | --------------------------------------------------------- |
| `Digest`          | A cryptographic digest/hash of data |
| `ARID`, `UUID`, `XID` | Unique identifiers for various purposes |
| `Salt`, `Nonce`   | Cryptographic primitives for random or pseudorandom data |
| `SymmetricKey`, `EncryptedMessage` | Types for symmetric encryption |
| `ECPrivateKey`, `ECPublicKey` | Elliptic curve cryptography keys |
| `Ed25519PrivateKey`, `Ed25519PublicKey` | Ed25519 cryptographic keys |
| `X25519PrivateKey`, `X25519PublicKey` | X25519 key agreement keys |
| `SigningPrivateKey`, `SigningPublicKey` | Keys for digital signatures |
| `MLDSAPrivateKey`, `MLDSAPublicKey` | Post-quantum digital signature keys |
| `MLKEMPrivateKey`, `MLKEMPublicKey` | Post-quantum key encapsulation keys |

### Reference Materials

These documents are essential for understanding the cryptographic primitives and standards implemented in this crate.

🚨 **NOTE**: Always refer to the relevant standards and specifications when documenting cryptographic primitives.

| Title | Description |
|-------|-------------|
| CBOR RFC 8949 | The CBOR data format specification |
| UR (Uniform Resources) | Blockchain Commons specification for encoding structured binary data |
| SSKR (Sharded Secret Key Reconstruction) | Specification for secret sharing |
| Post-quantum cryptography | NIST standards for quantum-resistant cryptography |

## Current Status and Roadmap

### 🟢 In Progress: Comprehensive Crate Documentation

- **Goal**: Enhance the documentation for the `bc-components` crate to improve usability and understanding. Document all public API elements, including structs, enums, and functions.

#### Documentation Quality Criteria

- **Comprehensive**: All public API elements have documentation
- **Contextual**: Documentation explains both "what" and "why"
- **Practical**: Examples demonstrate real-world usage
- **Consistent**: Uniform style and detail level across the codebase
- **Accessible**: Explanations suitable for developers not familiar with Rust, and Rust engineers not familiar with cryptography
- **Searchable**: Proper cross-references and keyword usage
- **Validated**: Examples compile and work correctly

#### Documentation Testing Guidelines

- **Doc Example Best Practices:**
  - Handle errors properly in examples that return `Result`
  - Use `no_run` for examples that can't be directly compiled/run in doc tests
  - Check constructors for type initialization in examples - some types may lack `Default` implementation
  - For internal/implementation types that users shouldn't directly interact with, clearly mark them as such in the documentation
  - Show typical usage patterns for each type, not all possible ways to use it
  - For cryptographic operations, include examples of key generation, signing/verification, encryption/decryption as appropriate
  - Refer to unit tests for examples of how to use the types
  - When demonstrating UR encoding/decoding, demonstrate using string representations
  - 🚨 **CRITICAL**: ALL trait implementations (`impl Trait for Type`) MUST have a single-line doc comment explaining the implementation's purpose - this includes common traits like `Default`, `From`, `TryFrom`, and any custom traits

#### Required Quality Checks

🚨 **CRITICAL**: Always perform these quality checks with EVERY documentation task BEFORE considering it complete:

1. **Fix all doc tests**:
   ```bash
   # Run from the bc-components directory, not the workspace root
   cd /path/to/bc-components && cargo test --doc
   ```
   Ensure all doc tests pass, and fix any failures immediately.

2. **Fix all Clippy lints**:
   ```bash
   # Run from the bc-components directory, not the workspace root
   cd /path/to/bc-components && cargo clippy -- -D warnings
   ```
   Address any Clippy warnings introduced by documentation changes.

🔴 **MANDATORY**: YOU MUST RUN THESE CHECKS YOURSELF after making changes, without waiting to be prompted. Documentation is not complete until all tests pass. NEVER mark a task as complete without running and passing these checks.

### Public API Items Needing Documentation

This section inventories all public API items that need documentation, ordered from simplest with least dependencies to most complex.

#### Core Cryptographic Primitives ✅

1. **✅ `Digest`** (`digest.rs`) - A cryptographic digest/hash of data
2. **✅ `DigestProvider`** (`digest_provider.rs`) - An interface for providing digests
3. **✅ `Nonce`** (`nonce.rs`) - A nonce (number used once) for cryptographic operations
4. **✅ `Salt`** (`salt.rs`) - A salt for cryptographic operations
5. **✅ `Seed`** (`seed.rs`) - A seed for deterministic key generation

#### Identifiers

1. **✅ `ARID`** (`id/arid.rs`) - An Apparently Random Identifier
2. **✅ `UUID`** (`id/uuid.rs`) - A Universally Unique Identifier
3. **✅ `XID`** (`id/xid.rs`) - An eXtensible Identifier
4. **✅ `URI`** (`id/uri.rs`) - A Uniform Resource Identifier
5. **✅ `XIDProvider`** (`id/mod.rs`) - Interface for providing XIDs

#### Symmetric Cryptography

1. **✅ `SymmetricKey`** (`symmetric/symmetric_key.rs`) - A key for symmetric encryption
2. **✅ `AuthenticationTag`** (`symmetric/authentication_tag.rs`) - Authentication tag for authenticated encryption
3. **✅ `EncryptedMessage`** (`symmetric/encrypted_message.rs`) - A symmetrically-encrypted message

#### Ed25519 and X25519

1. **✅ `Ed25519PrivateKey`**, **✅ `Ed25519PublicKey`** (`ed25519/ed25519_private_key.rs`, `ed25519/ed25519_public_key.rs`) - Ed25519 keys
2. **✅ `X25519PrivateKey`**, **✅ `X25519PublicKey`** (`x25519/x25519_private_key.rs`, `x25519/x25519_public_key.rs`) - X25519 keys

#### ECDSA

1. **✅ All the types in the `ec_key` module** (`ec_key/`) - ECDSA keys and signatures

#### Post-Quantum Cryptography

1. **✅ `MLDSALevel`**, **✅ `MLDSAPrivateKey`**, **✅ `MLDSAPublicKey`**, **✅ `MLDSASignature`** (`mldsa/`) - ML-DSA post-quantum signatures
2. **✅ `MLKEMLevel`**, **✅ `MLKEMPrivateKey`**, **✅ `MLKEMPublicKey`**, **✅ `MLKEMCiphertext`** (`mlkem/`) - ML-KEM post-quantum key encapsulation

#### Digital Signatures

1. **✅ `SigningPrivateKey`**, **✅ `SigningPublicKey`** (`signing/signing_private_key.rs`, `signing/signing_public_key.rs`) - Keys for digital signatures
2. **✅ `Signature`** (`signing/signature.rs`) - A digital signature
3. **✅ `Signer`**, **✅ `Verifier`** (`signing/signer.rs`) - Interfaces for signing and verification
4. **✅ `SignatureScheme`** (`signing/signature_scheme.rs`) - Enumeration of signature schemes

#### Key Encapsulation Mechanisms

1. **✅ `EncapsulationPrivateKey`**, **✅ `EncapsulationPublicKey`** (`encapsulation/encapsulation_private_key.rs`, `encapsulation/encapsulation_public_key.rs`) - KEM keys
2. **✅ `EncapsulationCiphertext`** (`encapsulation/encapsulation_ciphertext.rs`) - Ciphertext produced by KEM
3. **✅ `SealedMessage`** (`encapsulation/sealed_message.rs`) - A sealed message using KEM
4. **✅ `EncapsulationScheme`** (`encapsulation/encapsulation_scheme.rs`) - Enum of encapsulation schemes
5. **✅ `Encrypter`**, **✅ `Decrypter`** (`encrypter.rs`) - Interfaces for public key encryption/decryption

#### Secret Sharing

1. **✅ `SSKRGroupSpec`**, **✅ `SSKRSpec`**, **✅ `SSKRSecret`**, **✅ `SSKRShare`** (`sskr_mod.rs`) - SSKR secret sharing

#### Utilities

1. **✅ `HKDFRng`** (`hkdf_rng.rs`) - Random number generator based on HKDF
2. **✅ `keypair`, `keypair_using`** (`keypair.rs`) - Functions for generating keypairs

#### Compression

1. **✅ `Compressed`** (`compressed.rs`) - A compressed binary blob

### API Design Insights

The following insights about the API design of this crate have been learned during documentation:

1. **Cryptographic Flexibility**: The crate provides a uniform interface to different cryptographic schemes, allowing flexibility and future-proofing as cryptographic standards evolve.

2. **Post-Quantum Support**: The inclusion of ML-DSA and ML-KEM types demonstrates a forward-looking approach to cryptography in a post-quantum computing world.

3. **UR Serialization**: Many types support serialization to Uniform Resources (URs), enabling interoperability with other Blockchain Commons tools and libraries.

4. **CBOR Encoding**: Deterministic CBOR encoding ensures consistent serialization across platforms.

5. **Multiplatform Support**: The crate is designed to be used across different platforms and environments.

6. **Error Handling**: Comprehensive error handling for cryptographic operations ensures robust behavior.

7. **Testability**: Extensive test coverage, particularly important for cryptographic code.

8. **SSH Key Support**: Integration with SSH key formats for practical application interoperability.

### Documentation Lessons Learned

These are the key insights gained during the documentation process:

1. **Trait Implementation Documentation**: All trait implementations benefit from having a single-line doc comment that explains the purpose of the implementation. This significantly improves code readability and maintainability, especially for codebases with many trait implementations.

2. **CBOR and UR Patterns**: There is a consistent pattern across types for CBOR serialization and UR encoding. Most types in the crate follow the pattern:
   - Implement `CBORTagged` to define tags
   - Implement `CBORTaggedEncodable` for serialization
   - Implement `CBORTaggedDecodable` for deserialization
   - Implement `From<Type> for CBOR` and `TryFrom<CBOR> for Type` for conversions

3. **Type Conversion Patterns**: Many types implement similar conversion patterns:
   - `From<&Type> for Type` for cloning from references
   - `From<Type> for Vec<u8>` and `From<&Type> for Vec<u8>` for byte conversions
   - `AsRef<[u8]>` for providing byte slice references
   - `AsRef<Self>` for self-references

4. **Doc Testing Requirements**: Doctest examples need to be carefully constructed to compile and run successfully. This includes properly importing types, specifying correct type hints, and ensuring examples are self-contained.

5. **Cryptographic Primitive Relationships**: Core cryptographic primitives have clear roles with distinct purposes:
   - `Digest`: Immutable cryptographic hash used for verification and identification
   - `Nonce`: Fixed-size random number used once to prevent replay attacks
   - `Salt`: Variable-length random data used to decorrelate information
   - `Seed`: Source of entropy for deterministic key generation with metadata

### 🔵 FUTURE ENHANCEMENTS

- None planned at this time.
