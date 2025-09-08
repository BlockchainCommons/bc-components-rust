use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use super::MLDSA;
use crate::{Error, Result, tags};

/// A digital signature created with the ML-DSA post-quantum signature
/// algorithm.
///
/// `MLDSASignature` represents a digital signature created using the ML-DSA
/// (Module Lattice-based Digital Signature Algorithm) post-quantum algorithm.
/// It supports multiple security levels through the variants:
///
/// - `MLDSA44`: NIST security level 2 (roughly equivalent to AES-128)
/// - `MLDSA65`: NIST security level 3 (roughly equivalent to AES-192)
/// - `MLDSA87`: NIST security level 5 (roughly equivalent to AES-256)
///
/// ML-DSA signatures can be verified using the corresponding public key.
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
pub enum MLDSASignature {
    /// An ML-DSA44 signature (NIST security level 2)
    MLDSA44(Box<mldsa44::DetachedSignature>),
    /// An ML-DSA65 signature (NIST security level 3)
    MLDSA65(Box<mldsa65::DetachedSignature>),
    /// An ML-DSA87 signature (NIST security level 5)
    MLDSA87(Box<mldsa87::DetachedSignature>),
}

/// Implements equality comparison for ML-DSA signatures.
impl PartialEq for MLDSASignature {
    /// Compares two ML-DSA signatures for equality.
    ///
    /// Two ML-DSA signatures are equal if they have the same raw byte
    /// representation.
    fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }
}

impl MLDSASignature {
    /// Returns the security level of this ML-DSA signature.
    pub fn level(&self) -> MLDSA {
        match self {
            MLDSASignature::MLDSA44(_) => MLDSA::MLDSA44,
            MLDSASignature::MLDSA65(_) => MLDSA::MLDSA65,
            MLDSASignature::MLDSA87(_) => MLDSA::MLDSA87,
        }
    }

    /// Returns the size of this ML-DSA signature in bytes.
    pub fn size(&self) -> usize { self.level().signature_size() }

    /// Returns the raw bytes of this ML-DSA signature.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Creates an ML-DSA signature from raw bytes and a security level.
    ///
    /// # Parameters
    ///
    /// * `level` - The security level of the signature.
    /// * `bytes` - The raw bytes of the signature.
    ///
    /// # Returns
    ///
    /// An `MLDSASignature` if the bytes represent a valid signature for the
    /// given level, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid ML-DSA signature
    /// for the specified security level.
    pub fn from_bytes(level: MLDSA, bytes: &[u8]) -> Result<Self> {
        match level {
            MLDSA::MLDSA44 => Ok(MLDSASignature::MLDSA44(Box::new(
                mldsa44::DetachedSignature::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLDSA::MLDSA65 => Ok(MLDSASignature::MLDSA65(Box::new(
                mldsa65::DetachedSignature::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLDSA::MLDSA87 => Ok(MLDSASignature::MLDSA87(Box::new(
                mldsa87::DetachedSignature::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
        }
    }
}

impl AsRef<[u8]> for MLDSASignature {
    /// Returns the raw bytes of the signature.
    fn as_ref(&self) -> &[u8] {
        match self {
            MLDSASignature::MLDSA44(sig) => sig.as_bytes(),
            MLDSASignature::MLDSA65(sig) => sig.as_bytes(),
            MLDSASignature::MLDSA87(sig) => sig.as_bytes(),
        }
    }
}

/// Provides debug formatting for ML-DSA signatures.
impl std::fmt::Debug for MLDSASignature {
    /// Formats the signature as a string for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLDSASignature::MLDSA44(_) => f.write_str("MLDSA44Signature"),
            MLDSASignature::MLDSA65(_) => f.write_str("MLDSA65Signature"),
            MLDSASignature::MLDSA87(_) => f.write_str("MLDSA87Signature"),
        }
    }
}

/// Defines CBOR tags for ML-DSA signatures.
impl CBORTagged for MLDSASignature {
    /// Returns the CBOR tag for ML-DSA signatures.
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_MLDSA_SIGNATURE]) }
}

/// Converts an `MLDSASignature` to CBOR.
impl From<MLDSASignature> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: MLDSASignature) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for ML-DSA signatures.
impl CBORTaggedEncodable for MLDSASignature {
    /// Creates the untagged CBOR representation as an array with level and
    /// signature bytes.
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

/// Attempts to convert CBOR to an `MLDSASignature`.
impl TryFrom<CBOR> for MLDSASignature {
    type Error = dcbor::Error;

    /// Converts from tagged CBOR.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBOR decoding for ML-DSA signatures.
impl CBORTaggedDecodable for MLDSASignature {
    /// Creates an `MLDSASignature` from untagged CBOR.
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-DSA
    /// signature.
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("MLDSASignature must have two elements".into());
                }

                let level = MLDSA::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                Ok(MLDSASignature::from_bytes(level, &data)?)
            }
            _ => Err("MLDSASignature must be an array".into()),
        }
    }
}
