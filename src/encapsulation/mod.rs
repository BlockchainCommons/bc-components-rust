//! Key Encapsulation Mechanisms (KEM) for public key cryptography.
//!
//! This module provides a unified interface for key encapsulation mechanisms,
//! which are cryptographic algorithms used to securely exchange symmetric keys
//! using public key cryptography. The module supports both traditional (X25519)
//! and post-quantum (ML-KEM) encapsulation schemes.
//!
//! Key encapsulation mechanisms are used in hybrid cryptographic protocols
//! where:
//! - A shared secret is generated and encapsulated using a recipient's public
//!   key
//! - The recipient uses their private key to decapsulate (recover) the shared
//!   secret
//! - The shared secret is then used for symmetric encryption of the actual data
//!
//! ## Key Components
//!
//! - **EncapsulationScheme**: Enumeration of supported key encapsulation
//!   algorithms
//! - **EncapsulationPrivateKey**: Private keys for decapsulating shared secrets
//! - **EncapsulationPublicKey**: Public keys for encapsulating shared secrets
//! - **EncapsulationCiphertext**: Ciphertexts produced by the encapsulation
//!   process
//! - **SealedMessage**: A message encrypted using a key encapsulation mechanism
//!
//! ## Supported Schemes
//!
//! - **X25519**: Elliptic curve Diffie-Hellman key exchange using Curve25519
//! - **ML-KEM**: Module Lattice-based Key Encapsulation Mechanism
//!   (post-quantum) at different security levels (512, 768, 1024)
//!
//! ## Example Usage
//!
//! ```
//! use bc_components::{EncapsulationScheme, SealedMessage};
//!
//! // Generate keypair for the recipient (using default X25519 scheme)
//! let (recipient_private_key, recipient_public_key) =
//!     EncapsulationScheme::default().keypair();
//!
//! // Create a sealed message that only the recipient can decrypt
//! let plaintext = b"This message is for your eyes only";
//! let sealed_message = SealedMessage::new(plaintext, &recipient_public_key);
//!
//! // Recipient decrypts the message
//! let decrypted = sealed_message.decrypt(&recipient_private_key).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! For post-quantum security, use one of the ML-KEM schemes:
//!
//! ```ignore
//! use bc_components::{EncapsulationScheme, SealedMessage};
//!
//! // Generate post-quantum keypair for the recipient
//! let (recipient_private_key, recipient_public_key) =
//!     EncapsulationScheme::MLKEM768.keypair();
//!
//! // Create a quantum-resistant sealed message
//! let plaintext = b"Protected against quantum computers";
//! let sealed_message = SealedMessage::new(plaintext, &recipient_public_key);
//!
//! // Recipient decrypts the message
//! let decrypted = sealed_message.decrypt(&recipient_private_key).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//! ```

mod encapsulation_scheme;
pub use encapsulation_scheme::EncapsulationScheme;

mod encapsulation_private_key;
pub use encapsulation_private_key::EncapsulationPrivateKey;

mod encapsulation_public_key;
pub use encapsulation_public_key::EncapsulationPublicKey;

mod encapsulation_ciphertext;
pub use encapsulation_ciphertext::EncapsulationCiphertext;

mod sealed_message;
pub use sealed_message::SealedMessage;

#[cfg(test)]
mod tests {
    use crate::EncapsulationScheme;

    fn test_encapsulation(encapsulation: EncapsulationScheme) {
        let (private_key, public_key) = encapsulation.keypair();
        let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
        let secret2 =
            private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_x25519() {
        test_encapsulation(EncapsulationScheme::default());
    }

    #[test]
    #[cfg(feature = "pqcrypto")]
    fn test_mlkem512() {
        test_encapsulation(EncapsulationScheme::MLKEM512);
    }

    #[test]
    #[cfg(feature = "pqcrypto")]
    fn test_mlkem768() {
        test_encapsulation(EncapsulationScheme::MLKEM768);
    }

    #[test]
    #[cfg(feature = "pqcrypto")]
    fn test_mlkem1024() {
        test_encapsulation(EncapsulationScheme::MLKEM1024);
    }
}
