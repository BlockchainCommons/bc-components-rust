use crate::{Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use super::{MLDSA, MLDSASignature};
use crate::tags;

/// A private key for the ML-DSA post-quantum digital signature algorithm.
///
/// `MLDSAPrivateKey` represents a private key that can be used to create
/// digital signatures using the ML-DSA (Module Lattice-based Digital Signature
/// Algorithm) post-quantum algorithm. It supports multiple security levels
/// through the variants:
///
/// - `MLDSA44`: NIST security level 2 (roughly equivalent to AES-128)
/// - `MLDSA65`: NIST security level 3 (roughly equivalent to AES-192)
/// - `MLDSA87`: NIST security level 5 (roughly equivalent to AES-256)
///
/// # Security
///
/// ML-DSA private keys should be kept secure and never exposed. They provide
/// resistance against attacks from both classical and quantum computers.
///
/// # Examples
///
/// ```
/// use bc_components::MLDSA;
///
/// // Generate a keypair
/// let (private_key, public_key) = MLDSA::MLDSA44.keypair();
///
/// // Sign a message
/// let message = b"Hello, post-quantum world!";
/// let signature = private_key.sign(message);
/// ```
#[derive(Clone, PartialEq)]
pub enum MLDSAPrivateKey {
    /// An ML-DSA44 private key (NIST security level 2)
    MLDSA44(Box<mldsa44::SecretKey>),
    /// An ML-DSA65 private key (NIST security level 3)
    MLDSA65(Box<mldsa65::SecretKey>),
    /// An ML-DSA87 private key (NIST security level 5)
    MLDSA87(Box<mldsa87::SecretKey>),
}

impl MLDSAPrivateKey {
    /// Signs a message using this ML-DSA private key.
    ///
    /// # Parameters
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// An `MLDSASignature` for the message, using the same security level as
    /// this private key.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::MLDSA;
    ///
    /// let (private_key, _) = MLDSA::MLDSA44.keypair();
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(message);
    /// ```
    pub fn sign(&self, message: impl AsRef<[u8]>) -> MLDSASignature {
        match self {
            MLDSAPrivateKey::MLDSA44(sk) => MLDSASignature::MLDSA44(Box::new(
                mldsa44::detached_sign(message.as_ref(), sk),
            )),
            MLDSAPrivateKey::MLDSA65(sk) => MLDSASignature::MLDSA65(Box::new(
                mldsa65::detached_sign(message.as_ref(), sk),
            )),
            MLDSAPrivateKey::MLDSA87(sk) => MLDSASignature::MLDSA87(Box::new(
                mldsa87::detached_sign(message.as_ref(), sk),
            )),
        }
    }

    /// Returns the security level of this ML-DSA private key.
    pub fn level(&self) -> MLDSA {
        match self {
            MLDSAPrivateKey::MLDSA44(_) => MLDSA::MLDSA44,
            MLDSAPrivateKey::MLDSA65(_) => MLDSA::MLDSA65,
            MLDSAPrivateKey::MLDSA87(_) => MLDSA::MLDSA87,
        }
    }

    /// Returns the size of this ML-DSA private key in bytes.
    pub fn size(&self) -> usize { self.level().private_key_size() }

    /// Returns the raw bytes of this ML-DSA private key.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Creates an ML-DSA private key from raw bytes and a security level.
    ///
    /// # Parameters
    ///
    /// * `level` - The security level of the key.
    /// * `bytes` - The raw bytes of the key.
    ///
    /// # Returns
    ///
    /// An `MLDSAPrivateKey` if the bytes represent a valid key for the given
    /// level, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid ML-DSA private
    /// key for the specified security level.
    pub fn from_bytes(level: MLDSA, bytes: &[u8]) -> Result<Self> {
        match level {
            MLDSA::MLDSA44 => Ok(MLDSAPrivateKey::MLDSA44(Box::new(
                mldsa44::SecretKey::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLDSA::MLDSA65 => Ok(MLDSAPrivateKey::MLDSA65(Box::new(
                mldsa65::SecretKey::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLDSA::MLDSA87 => Ok(MLDSAPrivateKey::MLDSA87(Box::new(
                mldsa87::SecretKey::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
        }
    }
}

impl AsRef<[u8]> for MLDSAPrivateKey {
    /// Returns the private key as a byte slice.
    fn as_ref(&self) -> &[u8] {
        match self {
            MLDSAPrivateKey::MLDSA44(key) => key.as_bytes(),
            MLDSAPrivateKey::MLDSA65(key) => key.as_bytes(),
            MLDSAPrivateKey::MLDSA87(key) => key.as_bytes(),
        }
    }
}

/// Provides debug formatting for ML-DSA private keys.
impl std::fmt::Debug for MLDSAPrivateKey {
    /// Formats the private key as a string for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLDSAPrivateKey::MLDSA44(_) => f.write_str("MLDSA44PrivateKey"),
            MLDSAPrivateKey::MLDSA65(_) => f.write_str("MLDSA65PrivateKey"),
            MLDSAPrivateKey::MLDSA87(_) => f.write_str("MLDSA87PrivateKey"),
        }
    }
}

/// Defines CBOR tags for ML-DSA private keys.
impl CBORTagged for MLDSAPrivateKey {
    /// Returns the CBOR tag for ML-DSA private keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLDSA_PRIVATE_KEY])
    }
}

/// Converts an `MLDSAPrivateKey` to CBOR.
impl From<MLDSAPrivateKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: MLDSAPrivateKey) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for ML-DSA private keys.
impl CBORTaggedEncodable for MLDSAPrivateKey {
    /// Creates the untagged CBOR representation as an array with level and key
    /// bytes.
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

/// Attempts to convert CBOR to an `MLDSAPrivateKey`.
impl TryFrom<CBOR> for MLDSAPrivateKey {
    type Error = dcbor::Error;

    /// Converts from tagged CBOR.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBOR decoding for ML-DSA private keys.
impl CBORTaggedDecodable for MLDSAPrivateKey {
    /// Creates an `MLDSAPrivateKey` from untagged CBOR.
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-DSA
    /// private key.
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("MLDSAPrivateKey must have two elements".into());
                }

                let level = MLDSA::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                Ok(MLDSAPrivateKey::from_bytes(level, &data)?)
            }
            _ => Err("MLDSAPrivateKey must be an array".into()),
        }
    }
}
