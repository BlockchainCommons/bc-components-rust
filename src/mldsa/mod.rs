//! Module Lattice-based Digital Signature Algorithm (ML-DSA) types and
//! operations.
//!
//! This module provides types and operations for the ML-DSA post-quantum
//! digital signature algorithm, standardized by NIST. ML-DSA offers resistance
//! against attacks from both classical and quantum computers.
//!
//! The main components are:
//!
//! - `MLDSA`: Enumeration of security levels (MLDSA44, MLDSA65, MLDSA87)
//! - `MLDSAPrivateKey`: A private key for creating ML-DSA signatures
//! - `MLDSAPublicKey`: A public key for verifying ML-DSA signatures
//! - `MLDSASignature`: A digital signature produced by the ML-DSA algorithm
//!
//! ## Security Levels
//!
//! ML-DSA is implemented with three security levels:
//!
//! - **MLDSA44**: Provides NIST security level 2 (roughly equivalent to
//!   AES-128)
//! - **MLDSA65**: Provides NIST security level 3 (roughly equivalent to
//!   AES-192)
//! - **MLDSA87**: Provides NIST security level 5 (roughly equivalent to
//!   AES-256)
//!
//! Higher security levels provide stronger security guarantees but result in
//! larger key and signature sizes.
//!
//! ## Usage
//!
//! ML-DSA can be used for creating and verifying digital signatures that are
//! resistant to attacks by quantum computers:
//!
//! ```
//! use bc_components::MLDSA;
//!
//! // Generate a keypair with the desired security level
//! let (private_key, public_key) = MLDSA::MLDSA44.keypair();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = private_key.sign(message);
//!
//! // Verify the signature
//! assert!(public_key.verify(&signature, message).unwrap());
//! ```

mod mldsa_level;
pub use mldsa_level::MLDSA;

mod mldsa_private_key;
pub use mldsa_private_key::MLDSAPrivateKey;

mod mldsa_public_key;
pub use mldsa_public_key::MLDSAPublicKey;

mod mldsa_signature;
pub use mldsa_signature::MLDSASignature;

#[cfg(test)]
mod tests {
    use crate::MLDSA;

    const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_mldsa44_signing() {
        let (private_key, public_key) = MLDSA::MLDSA44.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(
            !public_key
                .verify(&signature, &MESSAGE[..MESSAGE.len() - 1])
                .unwrap()
        );
    }

    #[test]
    fn test_mldsa65_signing() {
        let (private_key, public_key) = MLDSA::MLDSA65.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(
            !public_key
                .verify(&signature, &MESSAGE[..MESSAGE.len() - 1])
                .unwrap()
        );
    }

    #[test]
    fn test_mldsa87_signing() {
        let (private_key, public_key) = MLDSA::MLDSA87.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(
            !public_key
                .verify(&signature, &MESSAGE[..MESSAGE.len() - 1])
                .unwrap()
        );
    }
}
