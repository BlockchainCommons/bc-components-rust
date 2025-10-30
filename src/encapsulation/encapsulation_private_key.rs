use bc_ur::prelude::*;

use crate::{
    Decrypter, Digest, EncapsulationCiphertext, EncapsulationScheme, Error,
    MLKEMPrivateKey, Reference, ReferenceProvider, Result, SymmetricKey,
    X25519PrivateKey, tags,
};

/// A private key used for key encapsulation mechanisms (KEM).
///
/// `EncapsulationPrivateKey` is an enum representing different types of private
/// keys that can be used for key encapsulation, including:
///
/// - X25519: Curve25519-based key exchange
/// - ML-KEM: Module Lattice-based Key Encapsulation Mechanism at various
///   security levels
///
/// These private keys are used to decrypt (decapsulate) shared secrets that
/// have been encapsulated with the corresponding public keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncapsulationPrivateKey {
    /// An X25519 private key
    X25519(X25519PrivateKey),
    /// An ML-KEM private key (post-quantum)
    MLKEM(MLKEMPrivateKey),
}

impl EncapsulationPrivateKey {
    /// Returns the encapsulation scheme associated with this private key.
    ///
    /// # Returns
    ///
    /// The encapsulation scheme (X25519, MLKEM512, MLKEM768, or MLKEM1024)
    /// that corresponds to this private key.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{
    ///     EncapsulationPrivateKey, EncapsulationScheme, X25519PrivateKey,
    /// };
    ///
    /// let x25519_private_key = X25519PrivateKey::new();
    /// let encapsulation_private_key =
    ///     EncapsulationPrivateKey::X25519(x25519_private_key);
    /// assert_eq!(
    ///     encapsulation_private_key.encapsulation_scheme(),
    ///     EncapsulationScheme::X25519
    /// );
    /// ```
    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            Self::MLKEM(pk) => match pk.level() {
                crate::MLKEM::MLKEM512 => EncapsulationScheme::MLKEM512,
                crate::MLKEM::MLKEM768 => EncapsulationScheme::MLKEM768,
                crate::MLKEM::MLKEM1024 => EncapsulationScheme::MLKEM1024,
            },
        }
    }

    /// Decapsulates a shared secret from a ciphertext using this private key.
    ///
    /// This method performs the decapsulation operation for key exchange. It
    /// takes an `EncapsulationCiphertext` and extracts the shared secret
    /// that was encapsulated using the corresponding public key.
    ///
    /// # Parameters
    ///
    /// * `ciphertext` - The encapsulation ciphertext containing the
    ///   encapsulated shared secret
    ///
    /// # Returns
    ///
    /// A `Result` containing the decapsulated `SymmetricKey` if successful,
    /// or an error if the decapsulation fails or if the ciphertext type doesn't
    /// match the private key type.
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
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate a key pair
    /// let (private_key, public_key) = EncapsulationScheme::default().keypair();
    ///
    /// // Encapsulate a new shared secret using the public key
    /// let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
    ///
    /// // Decapsulate the shared secret using the private key
    /// let secret2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
    ///
    /// // The original and decapsulated secrets should match
    /// assert_eq!(secret1, secret2);
    /// ```
    pub fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey> {
        match (self, ciphertext) {
            (
                EncapsulationPrivateKey::X25519(private_key),
                EncapsulationCiphertext::X25519(public_key),
            ) => Ok(private_key.shared_key_with(public_key)),
            (
                EncapsulationPrivateKey::MLKEM(private_key),
                EncapsulationCiphertext::MLKEM(ciphertext),
            ) => private_key.decapsulate_shared_secret(ciphertext),
            _ => Err(Error::crypto(format!(
                "Mismatched key encapsulation types. private key: {:?}, ciphertext: {:?}",
                self.encapsulation_scheme(),
                ciphertext.encapsulation_scheme()
            ))),
        }
    }
}

/// Implementation of the `Decrypter` trait for `EncapsulationPrivateKey`.
///
/// This allows `EncapsulationPrivateKey` to be used with the generic decryption
/// interface defined by the `Decrypter` trait.
impl Decrypter for EncapsulationPrivateKey {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.clone()
    }

    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey> {
        self.decapsulate_shared_secret(ciphertext)
    }
}

/// Conversion from `EncapsulationPrivateKey` to CBOR for serialization.
impl From<EncapsulationPrivateKey> for CBOR {
    fn from(private_key: EncapsulationPrivateKey) -> Self {
        match private_key {
            EncapsulationPrivateKey::X25519(private_key) => private_key.into(),
            EncapsulationPrivateKey::MLKEM(private_key) => private_key.into(),
        }
    }
}

/// Conversion from CBOR to `EncapsulationPrivateKey` for deserialization.
impl TryFrom<CBOR> for EncapsulationPrivateKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, dcbor::Error> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => match tag.value() {
                tags::TAG_X25519_PRIVATE_KEY => {
                    Ok(EncapsulationPrivateKey::X25519(
                        X25519PrivateKey::try_from(cbor)?,
                    ))
                }
                tags::TAG_MLKEM_PRIVATE_KEY => {
                    Ok(EncapsulationPrivateKey::MLKEM(
                        MLKEMPrivateKey::try_from(cbor)?,
                    ))
                }
                _ => {
                    Err(dcbor::Error::msg("Invalid encapsulation private key"))
                }
            },
            _ => Err(dcbor::Error::msg("Invalid encapsulation private key")),
        }
    }
}

impl ReferenceProvider for EncapsulationPrivateKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(self.to_cbor_data()))
    }
}

impl std::fmt::Display for EncapsulationPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_key = match self {
            EncapsulationPrivateKey::X25519(key) => key.to_string(),
            EncapsulationPrivateKey::MLKEM(key) => key.to_string(),
        };
        write!(
            f,
            "EncapsulationPrivateKey({}, {})",
            self.ref_hex_short(),
            display_key
        )
    }
}
