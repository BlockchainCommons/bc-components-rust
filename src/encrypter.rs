use crate::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey,
    Result, SymmetricKey,
};

/// A trait for types that can encapsulate shared secrets for public key
/// encryption.
///
/// The `Encrypter` trait defines an interface for encapsulating a shared secret
/// using a public key. This is a key part of hybrid encryption schemes, where a
/// shared symmetric key is encapsulated with a public key, and the recipient
/// uses their private key to recover the symmetric key.
///
/// Types implementing this trait provide the ability to:
/// 1. Access their encapsulation public key
/// 2. Generate and encapsulate new shared secrets
///
/// This trait is typically implemented by:
/// - Encapsulation public keys
/// - Higher-level types that contain or can generate encapsulation public keys
pub trait Encrypter {
    /// Returns the encapsulation public key for this encrypter.
    ///
    /// # Returns
    ///
    /// The encapsulation public key that should be used for encapsulation.
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;

    /// Encapsulates a new shared secret for the recipient.
    ///
    /// This method generates a new shared secret and encapsulates it using
    /// the encapsulation public key from this encrypter.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The generated shared secret as a `SymmetricKey`
    /// - The encapsulation ciphertext that can be sent to the recipient
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{EncapsulationScheme, Encrypter};
    ///
    /// // Generate a recipient keypair
    /// let (recipient_private_key, recipient_public_key) =
    ///     EncapsulationScheme::default().keypair();
    ///
    /// // Encapsulate a new shared secret
    /// let (shared_secret, ciphertext) =
    ///     recipient_public_key.encapsulate_new_shared_secret();
    /// ```
    fn encapsulate_new_shared_secret(
        &self,
    ) -> (SymmetricKey, EncapsulationCiphertext) {
        self.encapsulation_public_key()
            .encapsulate_new_shared_secret()
    }
}

/// A trait for types that can decapsulate shared secrets for public key
/// decryption.
///
/// The `Decrypter` trait defines an interface for decapsulating (recovering) a
/// shared secret using a private key. This is the counterpart to the
/// `Encrypter` trait and is used by the recipient of encapsulated messages.
///
/// Types implementing this trait provide the ability to:
/// 1. Access their encapsulation private key
/// 2. Decapsulate shared secrets from ciphertexts
///
/// This trait is typically implemented by:
/// - Encapsulation private keys
/// - Higher-level types that contain or can access encapsulation private keys
pub trait Decrypter {
    /// Returns the encapsulation private key for this decrypter.
    ///
    /// # Returns
    ///
    /// The encapsulation private key that should be used for decapsulation.
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;

    /// Decapsulates a shared secret from a ciphertext.
    ///
    /// This method recovers the shared secret that was encapsulated in the
    /// given ciphertext, using the private key from this decrypter.
    ///
    /// # Parameters
    ///
    /// * `ciphertext` - The encapsulation ciphertext containing the
    ///   encapsulated shared secret
    ///
    /// # Returns
    ///
    /// A `Result` containing the decapsulated `SymmetricKey` if successful,
    /// or an error if the decapsulation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext type doesn't match the private key type
    /// - The decapsulation operation fails
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{Decrypter, EncapsulationScheme, Encrypter};
    ///
    /// // Generate a keypair
    /// let (private_key, public_key) = EncapsulationScheme::default().keypair();
    ///
    /// // Encapsulate a new shared secret
    /// let (original_secret, ciphertext) =
    ///     public_key.encapsulate_new_shared_secret();
    ///
    /// // Decapsulate the shared secret
    /// let recovered_secret =
    ///     private_key.decapsulate_shared_secret(&ciphertext).unwrap();
    ///
    /// // The original and recovered secrets should match
    /// assert_eq!(original_secret, recovered_secret);
    /// ```
    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey> {
        self.encapsulation_private_key()
            .decapsulate_shared_secret(ciphertext)
    }
}
