use anyhow::{ anyhow, Result };
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::{ SecretKey, SharedSecret };
use dcbor::{
    tags_for_values,
    CBORCase,
    CBORTagged,
    CBORTaggedDecodable,
    CBORTaggedEncodable,
    Tag,
    CBOR,
};

use crate::{ tags, Decrypter, EncapsulationPrivateKey, SymmetricKey };

use super::{ MLKEMCiphertext, MLKEM };

/// A private key for the ML-KEM post-quantum key encapsulation mechanism.
///
/// `MLKEMPrivateKey` represents a private key that can be used to decapsulate shared secrets
/// using the ML-KEM (Module Lattice-based Key Encapsulation Mechanism) post-quantum algorithm.
/// It supports multiple security levels through the variants:
///
/// - `MLKEM512`: NIST security level 1 (roughly equivalent to AES-128), 1632 bytes
/// - `MLKEM768`: NIST security level 3 (roughly equivalent to AES-192), 2400 bytes
/// - `MLKEM1024`: NIST security level 5 (roughly equivalent to AES-256), 3168 bytes
///
/// # Security
///
/// ML-KEM private keys should be kept secure and never exposed. They provide
/// resistance against attacks from both classical and quantum computers.
///
/// # Examples
///
/// ```
/// use bc_components::MLKEM;
///
/// // Generate a keypair
/// let (private_key, public_key) = MLKEM::MLKEM512.keypair();
///
/// // Party A encapsulates a shared secret using the public key
/// let (shared_secret_a, ciphertext) = public_key.encapsulate_new_shared_secret();
///
/// // Party B decapsulates the shared secret using the private key and ciphertext
/// let shared_secret_b = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
///
/// // Both parties now have the same shared secret
/// assert_eq!(shared_secret_a, shared_secret_b);
/// ```
#[derive(Clone, PartialEq)]
pub enum MLKEMPrivateKey {
    /// An ML-KEM-512 private key (NIST security level 1)
    MLKEM512(Box<mlkem512::SecretKey>),
    /// An ML-KEM-768 private key (NIST security level 3)
    MLKEM768(Box<mlkem768::SecretKey>),
    /// An ML-KEM-1024 private key (NIST security level 5)
    MLKEM1024(Box<mlkem1024::SecretKey>),
}

impl Eq for MLKEMPrivateKey {}

/// Implements hashing for ML-KEM private keys.
impl std::hash::Hash for MLKEMPrivateKey {
    /// Hashes the raw bytes of the private key.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            MLKEMPrivateKey::MLKEM512(sk) => sk.as_bytes().hash(state),
            MLKEMPrivateKey::MLKEM768(sk) => sk.as_bytes().hash(state),
            MLKEMPrivateKey::MLKEM1024(sk) => sk.as_bytes().hash(state),
        }
    }
}

impl MLKEMPrivateKey {
    /// Returns the security level of this ML-KEM private key.
    pub fn level(&self) -> MLKEM {
        match self {
            MLKEMPrivateKey::MLKEM512(_) => MLKEM::MLKEM512,
            MLKEMPrivateKey::MLKEM768(_) => MLKEM::MLKEM768,
            MLKEMPrivateKey::MLKEM1024(_) => MLKEM::MLKEM1024,
        }
    }

    /// Returns the size of this ML-KEM private key in bytes.
    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    /// Returns the raw bytes of this ML-KEM private key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLKEMPrivateKey::MLKEM512(sk) => sk.as_ref().as_bytes(),
            MLKEMPrivateKey::MLKEM768(sk) => sk.as_ref().as_bytes(),
            MLKEMPrivateKey::MLKEM1024(sk) => sk.as_ref().as_bytes(),
        }
    }

    /// Creates an ML-KEM private key from raw bytes and a security level.
    ///
    /// # Parameters
    ///
    /// * `level` - The security level of the key.
    /// * `bytes` - The raw bytes of the key.
    ///
    /// # Returns
    ///
    /// An `MLKEMPrivateKey` if the bytes represent a valid key for the given level,
    /// or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid ML-KEM private key
    /// for the specified security level.
    pub fn from_bytes(level: MLKEM, bytes: &[u8]) -> Result<Self> {
        match level {
            MLKEM::MLKEM512 =>
                Ok(
                    MLKEMPrivateKey::MLKEM512(
                        Box::new(mlkem512::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?)
                    )
                ),
            MLKEM::MLKEM768 =>
                Ok(
                    MLKEMPrivateKey::MLKEM768(
                        Box::new(mlkem768::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?)
                    )
                ),
            MLKEM::MLKEM1024 =>
                Ok(
                    MLKEMPrivateKey::MLKEM1024(
                        Box::new(mlkem1024::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?)
                    )
                ),
        }
    }

    /// Decapsulates a shared secret from a ciphertext using this private key.
    ///
    /// # Parameters
    ///
    /// * `ciphertext` - The ciphertext containing the encapsulated shared secret.
    ///
    /// # Returns
    ///
    /// A `SymmetricKey` containing the decapsulated shared secret, or an error
    /// if decapsulation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the security level of the ciphertext doesn't match the
    /// security level of this private key, or if decapsulation fails for any other reason.
    ///
    /// # Panics
    ///
    /// Panics if the security level of the ciphertext doesn't match the security
    /// level of this private key.
    pub fn decapsulate_shared_secret(&self, ciphertext: &MLKEMCiphertext) -> Result<SymmetricKey> {
        match (self, ciphertext) {
            (MLKEMPrivateKey::MLKEM512(sk), MLKEMCiphertext::MLKEM512(ct)) => {
                let ss = mlkem512::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            (MLKEMPrivateKey::MLKEM768(sk), MLKEMCiphertext::MLKEM768(ct)) => {
                let ss = mlkem768::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            (MLKEMPrivateKey::MLKEM1024(sk), MLKEMCiphertext::MLKEM1024(ct)) => {
                let ss = mlkem1024::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            _ => panic!("MLKEM level mismatch"),
        }
    }
}

/// Implements the `Decrypter` trait for ML-KEM private keys.
impl Decrypter for MLKEMPrivateKey {
    /// Returns this key as an `EncapsulationPrivateKey`.
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        EncapsulationPrivateKey::MLKEM(self.clone())
    }
}

/// Provides debug formatting for ML-KEM private keys.
impl std::fmt::Debug for MLKEMPrivateKey {
    /// Formats the private key as a string for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLKEMPrivateKey::MLKEM512(_) => f.write_str("MLKEM512PrivateKey"),
            MLKEMPrivateKey::MLKEM768(_) => f.write_str("MLKEM768PrivateKey"),
            MLKEMPrivateKey::MLKEM1024(_) => f.write_str("MLKEM1024PrivateKey"),
        }
    }
}

/// Defines CBOR tags for ML-KEM private keys.
impl CBORTagged for MLKEMPrivateKey {
    /// Returns the CBOR tag for ML-KEM private keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLKEM_PRIVATE_KEY])
    }
}

/// Converts an `MLKEMPrivateKey` to CBOR.
impl From<MLKEMPrivateKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: MLKEMPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

/// Implements CBOR encoding for ML-KEM private keys.
impl CBORTaggedEncodable for MLKEMPrivateKey {
    /// Creates the untagged CBOR representation as an array with level and key bytes.
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

/// Attempts to convert CBOR to an `MLKEMPrivateKey`.
impl TryFrom<CBOR> for MLKEMPrivateKey {
    type Error = dcbor::Error;

    /// Converts from tagged CBOR.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBOR decoding for ML-KEM private keys.
impl CBORTaggedDecodable for MLKEMPrivateKey {
    /// Creates an `MLKEMPrivateKey` from untagged CBOR.
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-KEM private key.
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("MLKEMPrivateKey must have two elements".into());
                }

                let level = MLKEM::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                Ok(MLKEMPrivateKey::from_bytes(level, &data)?)
            }
            _ => {
                return Err("MLKEMPrivateKey must be an array".into());
            }
        }
    }
}
