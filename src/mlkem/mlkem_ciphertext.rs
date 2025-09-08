use crate::{Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::Ciphertext;

use super::MLKEM;
use crate::tags;

/// A ciphertext containing an encapsulated shared secret for ML-KEM.
///
/// `MLKEMCiphertext` represents a ciphertext produced by the ML-KEM
/// (Module Lattice-based Key Encapsulation Mechanism) post-quantum algorithm
/// during the encapsulation process. It contains an encapsulated shared secret
/// that can only be recovered by the corresponding private key.
///
/// It supports multiple security levels through the variants:
///
/// - `MLKEM512`: NIST security level 1 (roughly equivalent to AES-128), 768
///   bytes
/// - `MLKEM768`: NIST security level 3 (roughly equivalent to AES-192), 1088
///   bytes
/// - `MLKEM1024`: NIST security level 5 (roughly equivalent to AES-256), 1568
///   bytes
///
/// # Examples
///
/// ```
/// use bc_components::MLKEM;
///
/// // Generate a keypair
/// let (private_key, public_key) = MLKEM::MLKEM512.keypair();
///
/// // Encapsulate a shared secret using the public key
/// let (shared_secret_a, ciphertext) =
///     public_key.encapsulate_new_shared_secret();
///
/// // Decapsulate the shared secret using the private key
/// let shared_secret_b =
///     private_key.decapsulate_shared_secret(&ciphertext).unwrap();
///
/// // Both shared secrets should be the same
/// assert_eq!(shared_secret_a, shared_secret_b);
/// ```
#[derive(Clone, PartialEq)]
pub enum MLKEMCiphertext {
    /// An ML-KEM-512 ciphertext (NIST security level 1)
    MLKEM512(Box<mlkem512::Ciphertext>),
    /// An ML-KEM-768 ciphertext (NIST security level 3)
    MLKEM768(Box<mlkem768::Ciphertext>),
    /// An ML-KEM-1024 ciphertext (NIST security level 5)
    MLKEM1024(Box<mlkem1024::Ciphertext>),
}

impl MLKEMCiphertext {
    /// Returns the security level of this ML-KEM ciphertext.
    pub fn level(&self) -> MLKEM {
        match self {
            MLKEMCiphertext::MLKEM512(_) => MLKEM::MLKEM512,
            MLKEMCiphertext::MLKEM768(_) => MLKEM::MLKEM768,
            MLKEMCiphertext::MLKEM1024(_) => MLKEM::MLKEM1024,
        }
    }

    /// Returns the size of this ML-KEM ciphertext in bytes.
    pub fn size(&self) -> usize { self.level().ciphertext_size() }

    /// Returns the raw bytes of this ML-KEM ciphertext.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Creates an ML-KEM ciphertext from raw bytes and a security level.
    ///
    /// # Parameters
    ///
    /// * `level` - The security level of the ciphertext.
    /// * `bytes` - The raw bytes of the ciphertext.
    ///
    /// # Returns
    ///
    /// An `MLKEMCiphertext` if the bytes represent a valid ciphertext for the
    /// given level, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid ML-KEM ciphertext
    /// for the specified security level.
    pub fn from_bytes(level: MLKEM, bytes: &[u8]) -> Result<Self> {
        match level {
            MLKEM::MLKEM512 => Ok(MLKEMCiphertext::MLKEM512(Box::new(
                mlkem512::Ciphertext::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLKEM::MLKEM768 => Ok(MLKEMCiphertext::MLKEM768(Box::new(
                mlkem768::Ciphertext::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLKEM::MLKEM1024 => Ok(MLKEMCiphertext::MLKEM1024(Box::new(
                mlkem1024::Ciphertext::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
        }
    }
}

impl AsRef<[u8]> for MLKEMCiphertext {
    /// Returns the raw bytes of the ciphertext.
    fn as_ref(&self) -> &[u8] {
        match self {
            MLKEMCiphertext::MLKEM512(ct) => ct.as_ref().as_bytes(),
            MLKEMCiphertext::MLKEM768(ct) => ct.as_ref().as_bytes(),
            MLKEMCiphertext::MLKEM1024(ct) => ct.as_ref().as_bytes(),
        }
    }
}

/// Provides debug formatting for ML-KEM ciphertexts.
impl std::fmt::Debug for MLKEMCiphertext {
    /// Formats the ciphertext as a string for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLKEMCiphertext::MLKEM512(_) => f.write_str("MLKEM512Ciphertext"),
            MLKEMCiphertext::MLKEM768(_) => f.write_str("MLKEM768Ciphertext"),
            MLKEMCiphertext::MLKEM1024(_) => f.write_str("MLKEM1024Ciphertext"),
        }
    }
}

/// Defines CBOR tags for ML-KEM ciphertexts.
impl CBORTagged for MLKEMCiphertext {
    /// Returns the CBOR tag for ML-KEM ciphertexts.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLKEM_CIPHERTEXT])
    }
}

/// Converts an `MLKEMCiphertext` to CBOR.
impl From<MLKEMCiphertext> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: MLKEMCiphertext) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for ML-KEM ciphertexts.
impl CBORTaggedEncodable for MLKEMCiphertext {
    /// Creates the untagged CBOR representation as an array with level and
    /// ciphertext bytes.
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

/// Attempts to convert CBOR to an `MLKEMCiphertext`.
impl TryFrom<CBOR> for MLKEMCiphertext {
    type Error = dcbor::Error;

    /// Converts from tagged CBOR.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBOR decoding for ML-KEM ciphertexts.
impl CBORTaggedDecodable for MLKEMCiphertext {
    /// Creates an `MLKEMCiphertext` from untagged CBOR.
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-KEM
    /// ciphertext.
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("MLKEMCiphertext must have two elements".into());
                }

                let level = MLKEM::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                Ok(MLKEMCiphertext::from_bytes(level, &data)?)
            }
            _ => Err("MLKEMCiphertext must be an array".into()),
        }
    }
}
