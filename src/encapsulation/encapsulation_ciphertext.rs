use crate::{Error, Result};
use dcbor::prelude::*;

use crate::{EncapsulationScheme, MLKEMCiphertext, X25519PublicKey, tags};

/// A ciphertext produced by a key encapsulation mechanism (KEM).
///
/// `EncapsulationCiphertext` represents the output of a key encapsulation
/// operation where a shared secret has been encapsulated for secure
/// transmission. The ciphertext can only be used to recover the shared secret
/// by the holder of the corresponding private key.
///
/// This enum has two variants:
/// - `X25519`: For X25519 key agreement, this is the ephemeral public key
///   generated during encapsulation
/// - `MLKEM`: For ML-KEM post-quantum key encapsulation, this is the ML-KEM
///   ciphertext
#[derive(Debug, Clone, PartialEq)]
pub enum EncapsulationCiphertext {
    /// X25519 key agreement ciphertext (ephemeral public key)
    X25519(X25519PublicKey),
    /// ML-KEM post-quantum ciphertext
    MLKEM(MLKEMCiphertext),
}

impl EncapsulationCiphertext {
    /// Returns the X25519 public key if this is an X25519 ciphertext.
    ///
    /// # Returns
    ///
    /// A `Result` containing a reference to the X25519 public key if this is an
    /// X25519 ciphertext, or an error if it's not.
    ///
    /// # Errors
    ///
    /// Returns an error if this is not an X25519 ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{
    ///     EncapsulationScheme, X25519PrivateKey, X25519PublicKey,
    /// };
    ///
    /// // Generate a keypair
    /// let (private_key, public_key) = EncapsulationScheme::X25519.keypair();
    ///
    /// // Encapsulate a shared secret (creates an ephemeral keypair internally)
    /// let (_, ciphertext) = public_key.encapsulate_new_shared_secret();
    ///
    /// // Get the X25519 public key from the ciphertext
    /// if let Ok(ephemeral_public_key) = ciphertext.x25519_public_key() {
    ///     // This is an X25519 ephemeral public key
    ///     assert_eq!(ephemeral_public_key.data().len(), 32);
    /// }
    /// ```
    pub fn x25519_public_key(&self) -> Result<&X25519PublicKey> {
        match self {
            Self::X25519(public_key) => Ok(public_key),
            _ => Err(Error::crypto("Invalid key encapsulation type")),
        }
    }

    /// Returns the ML-KEM ciphertext if this is an ML-KEM ciphertext.
    ///
    /// # Returns
    ///
    /// A `Result` containing a reference to the ML-KEM ciphertext if this is an
    /// ML-KEM ciphertext, or an error if it's not.
    ///
    /// # Errors
    ///
    /// Returns an error if this is not an ML-KEM ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate an ML-KEM keypair
    /// let (private_key, public_key) = EncapsulationScheme::MLKEM768.keypair();
    ///
    /// // Encapsulate a shared secret
    /// let (_, ciphertext) = public_key.encapsulate_new_shared_secret();
    ///
    /// // Check if it's an ML-KEM ciphertext
    /// assert!(ciphertext.is_mlkem());
    ///
    /// // Get the ML-KEM ciphertext
    /// if let Ok(mlkem_ciphertext) = ciphertext.mlkem_ciphertext() {
    ///     // This is an ML-KEM ciphertext
    ///     assert_eq!(mlkem_ciphertext.level(), bc_components::MLKEM::MLKEM768);
    /// }
    /// ```
    pub fn mlkem_ciphertext(&self) -> Result<&MLKEMCiphertext> {
        match self {
            Self::MLKEM(ciphertext) => Ok(ciphertext),
            _ => Err(Error::crypto("Invalid key encapsulation type")),
        }
    }

    /// Returns true if this is an X25519 ciphertext.
    ///
    /// # Returns
    ///
    /// `true` if this is an X25519 ciphertext, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate an X25519 keypair
    /// let (_, public_key) = EncapsulationScheme::X25519.keypair();
    ///
    /// // Encapsulate a shared secret
    /// let (_, ciphertext) = public_key.encapsulate_new_shared_secret();
    ///
    /// // Check if it's an X25519 ciphertext
    /// assert!(ciphertext.is_x25519());
    /// assert!(!ciphertext.is_mlkem());
    /// ```
    pub fn is_x25519(&self) -> bool { matches!(self, Self::X25519(_)) }

    /// Returns true if this is an ML-KEM ciphertext.
    ///
    /// # Returns
    ///
    /// `true` if this is an ML-KEM ciphertext, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate an ML-KEM keypair
    /// let (_, public_key) = EncapsulationScheme::MLKEM768.keypair();
    ///
    /// // Encapsulate a shared secret
    /// let (_, ciphertext) = public_key.encapsulate_new_shared_secret();
    ///
    /// // Check if it's an ML-KEM ciphertext
    /// assert!(ciphertext.is_mlkem());
    /// assert!(!ciphertext.is_x25519());
    /// ```
    pub fn is_mlkem(&self) -> bool { matches!(self, Self::MLKEM(_)) }

    /// Returns the encapsulation scheme associated with this ciphertext.
    ///
    /// # Returns
    ///
    /// The encapsulation scheme (X25519, MLKEM512, MLKEM768, or MLKEM1024)
    /// that corresponds to this ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::EncapsulationScheme;
    ///
    /// // Generate a key pair using ML-KEM768
    /// let (_, public_key) = EncapsulationScheme::MLKEM768.keypair();
    ///
    /// // Encapsulate a shared secret
    /// let (_, ciphertext) = public_key.encapsulate_new_shared_secret();
    ///
    /// // Check the scheme
    /// assert_eq!(
    ///     ciphertext.encapsulation_scheme(),
    ///     EncapsulationScheme::MLKEM768
    /// );
    /// ```
    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            Self::MLKEM(ct) => match ct.level() {
                crate::MLKEM::MLKEM512 => EncapsulationScheme::MLKEM512,
                crate::MLKEM::MLKEM768 => EncapsulationScheme::MLKEM768,
                crate::MLKEM::MLKEM1024 => EncapsulationScheme::MLKEM1024,
            },
        }
    }
}

/// Conversion from `EncapsulationCiphertext` to CBOR for serialization.
impl From<EncapsulationCiphertext> for CBOR {
    fn from(ciphertext: EncapsulationCiphertext) -> Self {
        match ciphertext {
            EncapsulationCiphertext::X25519(public_key) => public_key.into(),
            EncapsulationCiphertext::MLKEM(ciphertext) => ciphertext.into(),
        }
    }
}

/// Conversion from CBOR to `EncapsulationCiphertext` for deserialization.
impl TryFrom<CBOR> for EncapsulationCiphertext {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, dcbor::Error> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => match tag.value() {
                tags::TAG_X25519_PUBLIC_KEY => {
                    Ok(EncapsulationCiphertext::X25519(
                        X25519PublicKey::try_from(cbor)?,
                    ))
                }
                tags::TAG_MLKEM_CIPHERTEXT => {
                    Ok(EncapsulationCiphertext::MLKEM(
                        MLKEMCiphertext::try_from(cbor)?,
                    ))
                }
                _ => Err(dcbor::Error::msg("Invalid encapsulation ciphertext")),
            },
            _ => Err(dcbor::Error::msg("Invalid encapsulation ciphertext")),
        }
    }
}
