use bc_ur::prelude::*;

#[cfg(feature = "pqcrypto")]
use crate::MLKEMPublicKey;
use crate::{
    Digest, EncapsulationCiphertext, EncapsulationScheme, Encrypter,
    PrivateKeyBase, Reference, ReferenceProvider, SymmetricKey,
    X25519PublicKey, tags,
};

/// A public key used for key encapsulation mechanisms (KEM).
///
/// `EncapsulationPublicKey` is an enum representing different types of public
/// keys that can be used for key encapsulation, including:
///
/// - X25519: Curve25519-based key exchange
/// - ML-KEM: Module Lattice-based Key Encapsulation Mechanism at various
///   security levels
///
/// These public keys are used to encrypt (encapsulate) shared secrets that can
/// only be decrypted (decapsulated) by the corresponding private key holder.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncapsulationPublicKey {
    /// An X25519 public key
    X25519(X25519PublicKey),
    /// An ML-KEM public key (post-quantum)
    #[cfg(feature = "pqcrypto")]
    MLKEM(MLKEMPublicKey),
}

impl EncapsulationPublicKey {
    /// Returns the encapsulation scheme associated with this public key.
    ///
    /// # Returns
    ///
    /// The encapsulation scheme (X25519, MLKEM512, MLKEM768, or MLKEM1024)
    /// that corresponds to this public key.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{EncapsulationScheme, X25519PrivateKey};
    ///
    /// // Generate a keypair
    /// let private_key = X25519PrivateKey::new();
    /// let public_key = private_key.public_key();
    ///
    /// // Convert to encapsulation public key
    /// let encapsulation_public_key =
    ///     bc_components::EncapsulationPublicKey::X25519(public_key);
    ///
    /// // Check the scheme
    /// assert_eq!(
    ///     encapsulation_public_key.encapsulation_scheme(),
    ///     EncapsulationScheme::X25519
    /// );
    /// ```
    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            #[cfg(feature = "pqcrypto")]
            Self::MLKEM(pk) => match pk.level() {
                crate::MLKEM::MLKEM512 => EncapsulationScheme::MLKEM512,
                crate::MLKEM::MLKEM768 => EncapsulationScheme::MLKEM768,
                crate::MLKEM::MLKEM1024 => EncapsulationScheme::MLKEM1024,
            },
        }
    }

    /// Encapsulates a new shared secret using this public key.
    ///
    /// This method performs the encapsulation operation for key exchange. It
    /// generates a new shared secret and encapsulates it using this public
    /// key.
    ///
    /// The encapsulation process differs based on the key type:
    /// - For X25519: Generates an ephemeral private/public key pair, derives a
    ///   shared secret using Diffie-Hellman, and returns the shared secret
    ///   along with the ephemeral public key
    /// - For ML-KEM: Uses the KEM encapsulation algorithm to generate and
    ///   encapsulate a random shared secret
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The generated shared secret as a `SymmetricKey`
    /// - The encapsulation ciphertext that can be sent to the private key
    ///   holder
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate a key pair using the default scheme (X25519)
    /// let (private_key, public_key) = EncapsulationScheme::default().keypair();
    ///
    /// // Encapsulate a new shared secret
    /// let (shared_secret, ciphertext) =
    ///     public_key.encapsulate_new_shared_secret();
    ///
    /// // The private key holder can recover the same shared secret
    /// let recovered_secret =
    ///     private_key.decapsulate_shared_secret(&ciphertext).unwrap();
    /// assert_eq!(shared_secret, recovered_secret);
    /// ```
    pub fn encapsulate_new_shared_secret(
        &self,
    ) -> (SymmetricKey, EncapsulationCiphertext) {
        match self {
            EncapsulationPublicKey::X25519(public_key) => {
                let emphemeral_sender = PrivateKeyBase::new();
                let ephemeral_private_key =
                    emphemeral_sender.x25519_private_key();
                let ephemeral_public_key = ephemeral_private_key.public_key();
                let shared_key =
                    ephemeral_private_key.shared_key_with(public_key);
                (
                    shared_key,
                    EncapsulationCiphertext::X25519(ephemeral_public_key),
                )
            }
            #[cfg(feature = "pqcrypto")]
            EncapsulationPublicKey::MLKEM(public_key) => {
                let (shared_key, ciphertext) =
                    public_key.encapsulate_new_shared_secret();
                (shared_key, EncapsulationCiphertext::MLKEM(ciphertext))
            }
        }
    }
}

/// Implementation of the `Encrypter` trait for `EncapsulationPublicKey`.
///
/// This allows `EncapsulationPublicKey` to be used with the generic encryption
/// interface defined by the `Encrypter` trait.
impl Encrypter for EncapsulationPublicKey {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        self.clone()
    }

    fn encapsulate_new_shared_secret(
        &self,
    ) -> (SymmetricKey, EncapsulationCiphertext) {
        self.encapsulate_new_shared_secret()
    }
}

/// Conversion from `EncapsulationPublicKey` to CBOR for serialization.
impl From<EncapsulationPublicKey> for CBOR {
    fn from(public_key: EncapsulationPublicKey) -> Self {
        match public_key {
            EncapsulationPublicKey::X25519(public_key) => public_key.into(),
            #[cfg(feature = "pqcrypto")]
            EncapsulationPublicKey::MLKEM(public_key) => public_key.into(),
        }
    }
}

/// Conversion from CBOR to `EncapsulationPublicKey` for deserialization.
impl TryFrom<CBOR> for EncapsulationPublicKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, dcbor::Error> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => match tag.value() {
                tags::TAG_X25519_PUBLIC_KEY => {
                    Ok(EncapsulationPublicKey::X25519(
                        X25519PublicKey::try_from(cbor)?,
                    ))
                }
                #[cfg(feature = "pqcrypto")]
                tags::TAG_MLKEM_PUBLIC_KEY => {
                    Ok(EncapsulationPublicKey::MLKEM(MLKEMPublicKey::try_from(
                        cbor,
                    )?))
                }
                _ => Err(dcbor::Error::msg("Invalid encapsulation public key")),
            },
            _ => Err(dcbor::Error::msg("Invalid encapsulation public key")),
        }
    }
}

impl ReferenceProvider for EncapsulationPublicKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(self.to_cbor_data()))
    }
}

impl std::fmt::Display for EncapsulationPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_key = match self {
            EncapsulationPublicKey::X25519(key) => key.to_string(),
            #[cfg(feature = "pqcrypto")]
            EncapsulationPublicKey::MLKEM(key) => key.to_string(),
        };
        write!(
            f,
            "EncapsulationPublicKey({}, {})",
            self.ref_hex_short(),
            display_key
        )
    }
}
