use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use super::{MLDSA, MLDSASignature};
use crate::{Error, Result, tags};

/// A public key for the ML-DSA post-quantum digital signature algorithm.
///
/// `MLDSAPublicKey` represents a public key that can be used to verify digital
/// signatures created with the ML-DSA (Module Lattice-based Digital Signature
/// Algorithm) post-quantum algorithm. It supports multiple security levels
/// through the variants:
///
/// - `MLDSA44`: NIST security level 2 (roughly equivalent to AES-128)
/// - `MLDSA65`: NIST security level 3 (roughly equivalent to AES-192)
/// - `MLDSA87`: NIST security level 5 (roughly equivalent to AES-256)
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
///
/// // Verify the signature
/// assert!(public_key.verify(&signature, message).unwrap());
/// ```
#[derive(Clone)]
pub enum MLDSAPublicKey {
    /// An ML-DSA44 public key (NIST security level 2)
    MLDSA44(Box<mldsa44::PublicKey>),
    /// An ML-DSA65 public key (NIST security level 3)
    MLDSA65(Box<mldsa65::PublicKey>),
    /// An ML-DSA87 public key (NIST security level 5)
    MLDSA87(Box<mldsa87::PublicKey>),
}

/// Implements equality comparison for ML-DSA public keys.
impl PartialEq for MLDSAPublicKey {
    /// Compares two ML-DSA public keys for equality.
    ///
    /// Two ML-DSA public keys are equal if they have the same security level
    /// and the same raw byte representation.
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for MLDSAPublicKey {}

/// Implements hashing for ML-DSA public keys.
impl std::hash::Hash for MLDSAPublicKey {
    /// Hashes both the security level and the raw bytes of the public key.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.level().hash(state);
        self.as_bytes().hash(state);
    }
}

impl MLDSAPublicKey {
    /// Verifies an ML-DSA signature for a message using this public key.
    ///
    /// # Parameters
    ///
    /// * `signature` - The signature to verify.
    /// * `message` - The message that was signed.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid for the message and this public
    /// key, `Ok(false)` if the signature is invalid, or an error if the
    /// security levels of the signature and public key don't match.
    ///
    /// # Errors
    ///
    /// Returns an error if the security level of the signature doesn't match
    /// the security level of this public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::MLDSA;
    ///
    /// let (private_key, public_key) = MLDSA::MLDSA44.keypair();
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(message);
    ///
    /// assert!(public_key.verify(&signature, message).unwrap());
    /// ```
    pub fn verify(
        &self,
        signature: &MLDSASignature,
        message: impl AsRef<[u8]>,
    ) -> Result<bool> {
        if signature.level() != self.level() {
            return Err(Error::LevelMismatch);
        }

        let verifies = match (self, signature) {
            (MLDSAPublicKey::MLDSA44(pk), MLDSASignature::MLDSA44(sig)) => {
                mldsa44::verify_detached_signature(sig, message.as_ref(), pk)
                    .is_ok()
            }
            (MLDSAPublicKey::MLDSA65(pk), MLDSASignature::MLDSA65(sig)) => {
                mldsa65::verify_detached_signature(sig, message.as_ref(), pk)
                    .is_ok()
            }
            (MLDSAPublicKey::MLDSA87(pk), MLDSASignature::MLDSA87(sig)) => {
                mldsa87::verify_detached_signature(sig, message.as_ref(), pk)
                    .is_ok()
            }
            _ => false,
        };

        Ok(verifies)
    }

    /// Returns the security level of this ML-DSA public key.
    pub fn level(&self) -> MLDSA {
        match self {
            MLDSAPublicKey::MLDSA44(_) => MLDSA::MLDSA44,
            MLDSAPublicKey::MLDSA65(_) => MLDSA::MLDSA65,
            MLDSAPublicKey::MLDSA87(_) => MLDSA::MLDSA87,
        }
    }

    /// Returns the size of this ML-DSA public key in bytes.
    pub fn size(&self) -> usize { self.level().public_key_size() }

    /// Returns the raw bytes of this ML-DSA public key.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Creates an ML-DSA public key from raw bytes and a security level.
    ///
    /// # Parameters
    ///
    /// * `level` - The security level of the key.
    /// * `bytes` - The raw bytes of the key.
    ///
    /// # Returns
    ///
    /// An `MLDSAPublicKey` if the bytes represent a valid key for the given
    /// level, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid ML-DSA public key
    /// for the specified security level.
    pub fn from_bytes(level: MLDSA, bytes: &[u8]) -> Result<Self> {
        match level {
            MLDSA::MLDSA44 => Ok(MLDSAPublicKey::MLDSA44(Box::new(
                mldsa44::PublicKey::from_bytes(bytes).map_err(|e| {
                    Error::post_quantum(format!(
                        "MLDSA44 public key error: {}",
                        e
                    ))
                })?,
            ))),
            MLDSA::MLDSA65 => Ok(MLDSAPublicKey::MLDSA65(Box::new(
                mldsa65::PublicKey::from_bytes(bytes).map_err(|e| {
                    Error::post_quantum(format!(
                        "MLDSA65 public key error: {}",
                        e
                    ))
                })?,
            ))),
            MLDSA::MLDSA87 => Ok(MLDSAPublicKey::MLDSA87(Box::new(
                mldsa87::PublicKey::from_bytes(bytes).map_err(|e| {
                    Error::post_quantum(format!(
                        "MLDSA87 public key error: {}",
                        e
                    ))
                })?,
            ))),
        }
    }
}

impl AsRef<[u8]> for MLDSAPublicKey {
    /// Returns the public key as a byte slice.
    fn as_ref(&self) -> &[u8] {
        match self {
            MLDSAPublicKey::MLDSA44(key) => key.as_bytes(),
            MLDSAPublicKey::MLDSA65(key) => key.as_bytes(),
            MLDSAPublicKey::MLDSA87(key) => key.as_bytes(),
        }
    }
}

/// Provides debug formatting for ML-DSA public keys.
impl std::fmt::Debug for MLDSAPublicKey {
    /// Formats the public key as a string for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLDSAPublicKey::MLDSA44(_) => f.write_str("MLDSA442PublicKey"),
            MLDSAPublicKey::MLDSA65(_) => f.write_str("MLDSA65PublicKey"),
            MLDSAPublicKey::MLDSA87(_) => f.write_str("MLDSA87PublicKey"),
        }
    }
}

/// Defines CBOR tags for ML-DSA public keys.
impl CBORTagged for MLDSAPublicKey {
    /// Returns the CBOR tag for ML-DSA public keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLDSA_PUBLIC_KEY])
    }
}

/// Converts an `MLDSAPublicKey` to CBOR.
impl From<MLDSAPublicKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: MLDSAPublicKey) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for ML-DSA public keys.
impl CBORTaggedEncodable for MLDSAPublicKey {
    /// Creates the untagged CBOR representation as an array with level and key
    /// bytes.
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

/// Attempts to convert CBOR to an `MLDSAPublicKey`.
impl TryFrom<CBOR> for MLDSAPublicKey {
    type Error = dcbor::Error;

    /// Converts from tagged CBOR.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBOR decoding for ML-DSA public keys.
impl CBORTaggedDecodable for MLDSAPublicKey {
    /// Creates an `MLDSAPublicKey` from untagged CBOR.
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-DSA
    /// public key.
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("MLDSAPublicKey must have two elements".into());
                }

                let level = MLDSA::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                Ok(MLDSAPublicKey::from_bytes(level, &data)?)
            }
            _ => Err("MLDSAPublicKey must be an array".into()),
        }
    }
}
