use anyhow::{Result, bail};
use bc_rand::RandomNumberGenerator;

use crate::{
    EncapsulationPrivateKey, EncapsulationPublicKey, MLKEM, X25519PrivateKey,
};

/// Supported key encapsulation mechanisms.
///
/// Key Encapsulation Mechanisms (KEMs) are cryptographic algorithms designed to
/// securely establish a shared secret between parties in public-key
/// cryptography. They are often used to encapsulate (wrap) symmetric keys for
/// secure key exchange.
///
/// This enum represents the various KEM schemes supported in this crate:
/// - X25519: A Diffie-Hellman key exchange mechanism using the Curve25519
///   elliptic curve
/// - ML-KEM (Module Lattice-based Key Encapsulation Mechanism): Post-quantum
///   secure KEM at different security levels (512, 768, 1024)
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum EncapsulationScheme {
    /// X25519 key agreement (default)
    #[default]
    X25519,
    /// ML-KEM512 post-quantum key encapsulation (NIST level 1)
    MLKEM512,
    /// ML-KEM768 post-quantum key encapsulation (NIST level 3)
    MLKEM768,
    /// ML-KEM1024 post-quantum key encapsulation (NIST level 5)
    MLKEM1024,
}

impl EncapsulationScheme {
    /// Generates a new random key pair for the specified encapsulation scheme.
    ///
    /// # Returns
    ///
    /// A tuple containing the private key and public key for the selected
    /// encapsulation scheme.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate a key pair using X25519 (default)
    /// let (private_key, public_key) = EncapsulationScheme::default().keypair();
    ///
    /// // Generate a key pair using ML-KEM768
    /// let (private_key, public_key) = EncapsulationScheme::MLKEM768.keypair();
    /// ```
    pub fn keypair(self) -> (EncapsulationPrivateKey, EncapsulationPublicKey) {
        match self {
            EncapsulationScheme::X25519 => {
                let (private_key, public_key) = X25519PrivateKey::keypair();
                (
                    EncapsulationPrivateKey::X25519(private_key),
                    EncapsulationPublicKey::X25519(public_key),
                )
            }
            EncapsulationScheme::MLKEM512 => {
                let (private_key, public_key) = MLKEM::MLKEM512.keypair();
                (
                    EncapsulationPrivateKey::MLKEM(private_key),
                    EncapsulationPublicKey::MLKEM(public_key),
                )
            }
            EncapsulationScheme::MLKEM768 => {
                let (private_key, public_key) = MLKEM::MLKEM768.keypair();
                (
                    EncapsulationPrivateKey::MLKEM(private_key),
                    EncapsulationPublicKey::MLKEM(public_key),
                )
            }
            EncapsulationScheme::MLKEM1024 => {
                let (private_key, public_key) = MLKEM::MLKEM1024.keypair();
                (
                    EncapsulationPrivateKey::MLKEM(private_key),
                    EncapsulationPublicKey::MLKEM(public_key),
                )
            }
        }
    }

    /// Generates a deterministic key pair using the provided random number
    /// generator.
    ///
    /// # Parameters
    ///
    /// * `rng` - A mutable reference to a random number generator
    ///
    /// # Returns
    ///
    /// A Result containing a tuple with the private key and public key if
    /// successful, or an error if deterministic key generation is not
    /// supported for the selected scheme.
    ///
    /// # Errors
    ///
    /// Returns an error if deterministic key generation is not supported for
    /// the selected encapsulation scheme (currently only X25519 supports
    /// this).
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    /// use bc_rand::SecureRandomNumberGenerator;
    ///
    /// let mut rng = SecureRandomNumberGenerator;
    /// let result = EncapsulationScheme::X25519.keypair_using(&mut rng);
    /// assert!(result.is_ok());
    ///
    /// // ML-KEM schemes don't support deterministic key generation
    /// let result = EncapsulationScheme::MLKEM512.keypair_using(&mut rng);
    /// assert!(result.is_err());
    /// ```
    pub fn keypair_using(
        self,
        rng: &mut impl RandomNumberGenerator,
    ) -> Result<(EncapsulationPrivateKey, EncapsulationPublicKey)> {
        match self {
            EncapsulationScheme::X25519 => {
                let (private_key, public_key) =
                    X25519PrivateKey::keypair_using(rng);
                Ok((
                    EncapsulationPrivateKey::X25519(private_key),
                    EncapsulationPublicKey::X25519(public_key),
                ))
            }
            _ => bail!(
                "Deterministic keypair generation not supported for this encapsulation scheme"
            ),
        }
    }
}
