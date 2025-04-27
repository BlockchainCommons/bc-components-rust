use anyhow::{ bail, Error, Result };
use pqcrypto_mlkem::*;
use dcbor::CBOR;

use super::{ MLKEMPrivateKey, MLKEMPublicKey };

/// Security levels for the ML-KEM post-quantum key encapsulation mechanism.
///
/// ML-KEM (Module Lattice-based Key Encapsulation Mechanism) is a post-quantum
/// key encapsulation mechanism standardized by NIST. It provides resistance
/// against attacks from both classical and quantum computers.
///
/// Each security level offers different trade-offs between security, performance,
/// and key/ciphertext sizes:
///
/// - `MLKEM512`: NIST security level 1 (roughly equivalent to AES-128)
/// - `MLKEM768`: NIST security level 3 (roughly equivalent to AES-192)
/// - `MLKEM1024`: NIST security level 5 (roughly equivalent to AES-256)
///
/// The numeric values (512, 768, 1024) correspond to the parameter sets and are used
/// in CBOR serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MLKEM {
    /// ML-KEM-512 (NIST security level 1, roughly equivalent to AES-128)
    MLKEM512 = 512,
    /// ML-KEM-768 (NIST security level 3, roughly equivalent to AES-192)
    MLKEM768 = 768,
    /// ML-KEM-1024 (NIST security level 5, roughly equivalent to AES-256)
    MLKEM1024 = 1024,
}

impl MLKEM {
    /// The size of a shared secret in bytes (32 bytes for all security levels).
    pub const SHARED_SECRET_SIZE: usize = mlkem512::shared_secret_bytes();

    /// Generates a new ML-KEM keypair with the specified security level.
    ///
    /// # Returns
    /// A tuple containing the private key and public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::MLKEM;
    ///
    /// let (private_key, public_key) = MLKEM::MLKEM512.keypair();
    /// ```
    pub fn keypair(self) -> (MLKEMPrivateKey, MLKEMPublicKey) {
        match self {
            MLKEM::MLKEM512 => {
                let (pk, sk) = mlkem512::keypair();
                (MLKEMPrivateKey::MLKEM512(sk.into()), MLKEMPublicKey::MLKEM512(pk.into()))
            }
            MLKEM::MLKEM768 => {
                let (pk, sk) = mlkem768::keypair();
                (MLKEMPrivateKey::MLKEM768(sk.into()), MLKEMPublicKey::MLKEM768(pk.into()))
            }
            MLKEM::MLKEM1024 => {
                let (pk, sk) = mlkem1024::keypair();
                (MLKEMPrivateKey::MLKEM1024(sk.into()), MLKEMPublicKey::MLKEM1024(pk.into()))
            }
        }
    }

    /// Returns the size of a private key in bytes for this security level.
    ///
    /// # Returns
    /// - `MLKEM512`: 1632 bytes
    /// - `MLKEM768`: 2400 bytes
    /// - `MLKEM1024`: 3168 bytes
    pub fn private_key_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::secret_key_bytes(),
            MLKEM::MLKEM768 => mlkem768::secret_key_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::secret_key_bytes(),
        }
    }

    /// Returns the size of a public key in bytes for this security level.
    ///
    /// # Returns
    /// - `MLKEM512`: 800 bytes
    /// - `MLKEM768`: 1184 bytes
    /// - `MLKEM1024`: 1568 bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::public_key_bytes(),
            MLKEM::MLKEM768 => mlkem768::public_key_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::public_key_bytes(),
        }
    }

    /// Returns the size of a shared secret in bytes for this security level.
    ///
    /// This is 32 bytes for all security levels.
    pub fn shared_secret_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::shared_secret_bytes(),
            MLKEM::MLKEM768 => mlkem768::shared_secret_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::shared_secret_bytes(),
        }
    }

    /// Returns the size of a ciphertext in bytes for this security level.
    ///
    /// # Returns
    /// - `MLKEM512`: 768 bytes
    /// - `MLKEM768`: 1088 bytes
    /// - `MLKEM1024`: 1568 bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::ciphertext_bytes(),
            MLKEM::MLKEM768 => mlkem768::ciphertext_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::ciphertext_bytes(),
        }
    }
}

/// Converts an `MLKEM` value to CBOR.
impl From<MLKEM> for CBOR {
    /// Converts to the numeric security level value (512, 768, or 1024).
    fn from(mlkem: MLKEM) -> Self {
        (mlkem as u32).into()
    }
}

/// Attempts to convert CBOR to an `MLKEM` value.
impl TryFrom<CBOR> for MLKEM {
    type Error = Error;

    /// Converts from a CBOR-encoded security level (512, 768, or 1024).
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-KEM level.
    fn try_from(cbor: CBOR) -> Result<Self> {
        let level = u32::try_from(cbor)?;
        match level {
            512 => Ok(MLKEM::MLKEM512),
            768 => Ok(MLKEM::MLKEM768),
            1024 => Ok(MLKEM::MLKEM1024),
            _ => bail!("Invalid MLKEM level: {}", level),
        }
    }
}
