use crate::{Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::{PublicKey, SharedSecret};

use super::{MLKEM, MLKEMCiphertext};
use crate::{SymmetricKey, tags};

/// A public key for the ML-KEM post-quantum key encapsulation mechanism.
///
/// `MLKEMPublicKey` represents a public key that can be used to encapsulate
/// shared secrets using the ML-KEM (Module Lattice-based Key Encapsulation
/// Mechanism) post-quantum algorithm. It supports multiple security levels
/// through the variants:
///
/// - `MLKEM512`: NIST security level 1 (roughly equivalent to AES-128), 800
///   bytes
/// - `MLKEM768`: NIST security level 3 (roughly equivalent to AES-192), 1184
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
/// let (shared_secret, ciphertext) =
///     public_key.encapsulate_new_shared_secret();
/// ```
#[derive(Clone)]
pub enum MLKEMPublicKey {
    /// An ML-KEM-512 public key (NIST security level 1)
    MLKEM512(Box<mlkem512::PublicKey>),
    /// An ML-KEM-768 public key (NIST security level 3)
    MLKEM768(Box<mlkem768::PublicKey>),
    /// An ML-KEM-1024 public key (NIST security level 5)
    MLKEM1024(Box<mlkem1024::PublicKey>),
}

/// Implements equality comparison for ML-KEM public keys.
impl PartialEq for MLKEMPublicKey {
    /// Compares two ML-KEM public keys for equality.
    ///
    /// Two ML-KEM public keys are equal if they have the same security level
    /// and the same raw byte representation.
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for MLKEMPublicKey {}

/// Implements hashing for ML-KEM public keys.
impl std::hash::Hash for MLKEMPublicKey {
    /// Hashes both the security level and the raw bytes of the public key.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.level().hash(state);
        self.as_bytes().hash(state);
    }
}

impl MLKEMPublicKey {
    /// Returns the security level of this ML-KEM public key.
    pub fn level(&self) -> MLKEM {
        match self {
            MLKEMPublicKey::MLKEM512(_) => MLKEM::MLKEM512,
            MLKEMPublicKey::MLKEM768(_) => MLKEM::MLKEM768,
            MLKEMPublicKey::MLKEM1024(_) => MLKEM::MLKEM1024,
        }
    }

    /// Returns the size of this ML-KEM public key in bytes.
    pub fn size(&self) -> usize { self.level().public_key_size() }

    /// Returns the raw bytes of this ML-KEM public key.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Creates an ML-KEM public key from raw bytes and a security level.
    ///
    /// # Parameters
    ///
    /// * `level` - The security level of the key.
    /// * `bytes` - The raw bytes of the key.
    ///
    /// # Returns
    ///
    /// An `MLKEMPublicKey` if the bytes represent a valid key for the given
    /// level, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid ML-KEM public key
    /// for the specified security level.
    pub fn from_bytes(level: MLKEM, bytes: &[u8]) -> Result<Self> {
        match level {
            MLKEM::MLKEM512 => Ok(MLKEMPublicKey::MLKEM512(Box::new(
                mlkem512::PublicKey::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLKEM::MLKEM768 => Ok(MLKEMPublicKey::MLKEM768(Box::new(
                mlkem768::PublicKey::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
            MLKEM::MLKEM1024 => Ok(MLKEMPublicKey::MLKEM1024(Box::new(
                mlkem1024::PublicKey::from_bytes(bytes)
                    .map_err(|e| Error::post_quantum(e.to_string()))?,
            ))),
        }
    }

    /// Encapsulates a new shared secret using this public key.
    ///
    /// This method generates a random shared secret and encapsulates it using
    /// this public key, producing a ciphertext that can only be decapsulated
    /// by the corresponding private key.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A `SymmetricKey` with the shared secret (32 bytes)
    /// - An `MLKEMCiphertext` with the encapsulated shared secret
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::MLKEM;
    ///
    /// // Generate a keypair
    /// let (private_key, public_key) = MLKEM::MLKEM512.keypair();
    ///
    /// // Encapsulate a shared secret
    /// let (shared_secret, ciphertext) =
    ///     public_key.encapsulate_new_shared_secret();
    ///
    /// // The private key holder can decapsulate the same shared secret
    /// let decapsulated_secret =
    ///     private_key.decapsulate_shared_secret(&ciphertext).unwrap();
    /// assert_eq!(shared_secret, decapsulated_secret);
    /// ```
    pub fn encapsulate_new_shared_secret(
        &self,
    ) -> (SymmetricKey, MLKEMCiphertext) {
        match self {
            MLKEMPublicKey::MLKEM512(pk) => {
                let (ss, ct) = mlkem512::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    MLKEMCiphertext::MLKEM512(ct.into()),
                )
            }
            MLKEMPublicKey::MLKEM768(pk) => {
                let (ss, ct) = mlkem768::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    MLKEMCiphertext::MLKEM768(ct.into()),
                )
            }
            MLKEMPublicKey::MLKEM1024(pk) => {
                let (ss, ct) = mlkem1024::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    MLKEMCiphertext::MLKEM1024(ct.into()),
                )
            }
        }
    }
}

impl AsRef<[u8]> for MLKEMPublicKey {
    /// Returns the raw bytes of the public key.
    fn as_ref(&self) -> &[u8] {
        match self {
            MLKEMPublicKey::MLKEM512(pk) => pk.as_ref().as_bytes(),
            MLKEMPublicKey::MLKEM768(pk) => pk.as_ref().as_bytes(),
            MLKEMPublicKey::MLKEM1024(pk) => pk.as_ref().as_bytes(),
        }
    }
}

/// Provides debug formatting for ML-KEM public keys.
impl std::fmt::Debug for MLKEMPublicKey {
    /// Formats the public key as a string for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLKEMPublicKey::MLKEM512(_) => f.write_str("MLKEM512PublicKey"),
            MLKEMPublicKey::MLKEM768(_) => f.write_str("MLKEM768PublicKey"),
            MLKEMPublicKey::MLKEM1024(_) => f.write_str("MLKEM1024PublicKey"),
        }
    }
}

/// Defines CBOR tags for ML-KEM public keys.
impl CBORTagged for MLKEMPublicKey {
    /// Returns the CBOR tag for ML-KEM public keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLKEM_PUBLIC_KEY])
    }
}

/// Converts an `MLKEMPublicKey` to CBOR.
impl From<MLKEMPublicKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: MLKEMPublicKey) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for ML-KEM public keys.
impl CBORTaggedEncodable for MLKEMPublicKey {
    /// Creates the untagged CBOR representation as an array with level and key
    /// bytes.
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

/// Attempts to convert CBOR to an `MLKEMPublicKey`.
impl TryFrom<CBOR> for MLKEMPublicKey {
    type Error = dcbor::Error;

    /// Converts from tagged CBOR.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBOR decoding for ML-KEM public keys.
impl CBORTaggedDecodable for MLKEMPublicKey {
    /// Creates an `MLKEMPublicKey` from untagged CBOR.
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-KEM
    /// public key.
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("MLKEMPublicKey must have two elements".into());
                }

                let level = MLKEM::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                Ok(MLKEMPublicKey::from_bytes(level, &data)?)
            }
            _ => Err("MLKEMPublicKey must be an array".into()),
        }
    }
}
