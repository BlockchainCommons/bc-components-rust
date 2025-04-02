//! Module Lattice-based Key Encapsulation Mechanism (ML-KEM) types and operations.
//!
//! This module provides types and operations for the ML-KEM post-quantum key
//! encapsulation mechanism, standardized by NIST. ML-KEM offers resistance against
//! attacks from both classical and quantum computers.
//!
//! The main components are:
//!
//! - `MLKEM`: Enumeration of security levels (MLKEM512, MLKEM768, MLKEM1024)
//! - `MLKEMPrivateKey`: A private key for decapsulating shared secrets
//! - `MLKEMPublicKey`: A public key for encapsulating shared secrets
//! - `MLKEMCiphertext`: A ciphertext containing an encapsulated shared secret
//!
//! ## Security Levels
//!
//! ML-KEM is implemented with three security levels:
//!
//! - **MLKEM512**: Provides NIST security level 1 (roughly equivalent to AES-128)
//! - **MLKEM768**: Provides NIST security level 3 (roughly equivalent to AES-192)
//! - **MLKEM1024**: Provides NIST security level 5 (roughly equivalent to AES-256)
//!
//! Higher security levels provide stronger security guarantees but result in larger
//! key and ciphertext sizes.
//!
//! ## Usage
//!
//! ML-KEM can be used for establishing shared secrets between parties:
//!
//! ```
//! use bc_components::MLKEM;
//!
//! // Generate a keypair with the desired security level
//! let (private_key, public_key) = MLKEM::MLKEM512.keypair();
//!
//! // Party A encapsulates a shared secret using the public key
//! let (shared_secret_a, ciphertext) = public_key.encapsulate_new_shared_secret();
//!
//! // Party B decapsulates the shared secret using the private key and ciphertext
//! let shared_secret_b = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
//!
//! // Both parties now have the same shared secret
//! assert_eq!(shared_secret_a, shared_secret_b);
//! ```

mod mlkem_level;
pub use mlkem_level::MLKEM;

mod mlkem_ciphertext;
pub use mlkem_ciphertext::MLKEMCiphertext;

mod mlkem_private_key;
pub use mlkem_private_key::MLKEMPrivateKey;

mod mlkem_public_key;
pub use mlkem_public_key::MLKEMPublicKey;

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_mlkem512() {
        let (private_key, public_key) = MLKEM::MLKEM512.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 1632);
        assert_eq!(public_key.size(), 800);
        assert_eq!(ciphertext.size(), 768);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_mlkem768() {
        let (private_key, public_key) = MLKEM::MLKEM768.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 2400);
        assert_eq!(public_key.size(), 1184);
        assert_eq!(ciphertext.size(), 1088);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_mlkem1024() {
        let (private_key, public_key) = MLKEM::MLKEM1024.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 3168);
        assert_eq!(public_key.size(), 1568);
        assert_eq!(ciphertext.size(), 1568);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }
}
