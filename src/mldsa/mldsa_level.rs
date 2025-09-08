use crate::{Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;

use super::{MLDSAPrivateKey, MLDSAPublicKey};

/// Security levels for the ML-DSA post-quantum digital signature algorithm.
///
/// ML-DSA (Module Lattice-based Digital Signature Algorithm) is a post-quantum
/// digital signature algorithm standardized by NIST. It provides resistance
/// against attacks from both classical and quantum computers.
///
/// Each security level offers different trade-offs between security,
/// performance, and key/signature sizes:
///
/// - `MLDSA44`: NIST security level 2 (roughly equivalent to AES-128)
/// - `MLDSA65`: NIST security level 3 (roughly equivalent to AES-192)
/// - `MLDSA87`: NIST security level 5 (roughly equivalent to AES-256)
///
/// The numeric values (2, 3, 5) correspond to the NIST security levels and are
/// used in CBOR serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MLDSA {
    /// ML-DSA Level 2 (NIST security level 2, roughly equivalent to AES-128)
    MLDSA44 = 2,
    /// ML-DSA Level 3 (NIST security level 3, roughly equivalent to AES-192)
    MLDSA65 = 3,
    /// ML-DSA Level 5 (NIST security level 5, roughly equivalent to AES-256)
    MLDSA87 = 5,
}

impl MLDSA {
    /// Generates a new ML-DSA keypair with the specified security level.
    ///
    /// # Returns
    /// A tuple containing the private key and public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::MLDSA;
    ///
    /// let (private_key, public_key) = MLDSA::MLDSA44.keypair();
    /// ```
    pub fn keypair(self) -> (MLDSAPrivateKey, MLDSAPublicKey) {
        match self {
            MLDSA::MLDSA44 => {
                let (pk, sk) = mldsa44::keypair();
                (
                    MLDSAPrivateKey::MLDSA44(Box::new(sk)),
                    MLDSAPublicKey::MLDSA44(Box::new(pk)),
                )
            }
            MLDSA::MLDSA65 => {
                let (pk, sk) = mldsa65::keypair();
                (
                    MLDSAPrivateKey::MLDSA65(Box::new(sk)),
                    MLDSAPublicKey::MLDSA65(Box::new(pk)),
                )
            }
            MLDSA::MLDSA87 => {
                let (pk, sk) = mldsa87::keypair();
                (
                    MLDSAPrivateKey::MLDSA87(Box::new(sk)),
                    MLDSAPublicKey::MLDSA87(Box::new(pk)),
                )
            }
        }
    }

    /// Returns the size of a private key in bytes for this security level.
    pub fn private_key_size(&self) -> usize {
        match self {
            MLDSA::MLDSA44 => mldsa44::secret_key_bytes(),
            MLDSA::MLDSA65 => mldsa65::secret_key_bytes(),
            MLDSA::MLDSA87 => mldsa87::secret_key_bytes(),
        }
    }

    /// Returns the size of a public key in bytes for this security level.
    pub fn public_key_size(&self) -> usize {
        match self {
            MLDSA::MLDSA44 => mldsa44::public_key_bytes(),
            MLDSA::MLDSA65 => mldsa65::public_key_bytes(),
            MLDSA::MLDSA87 => mldsa87::public_key_bytes(),
        }
    }

    /// Returns the size of a signature in bytes for this security level.
    pub fn signature_size(&self) -> usize {
        match self {
            MLDSA::MLDSA44 => mldsa44::signature_bytes(),
            MLDSA::MLDSA65 => mldsa65::signature_bytes(),
            MLDSA::MLDSA87 => mldsa87::signature_bytes(),
        }
    }
}

/// Converts an `MLDSA` value to CBOR.
impl From<MLDSA> for CBOR {
    /// Converts to the numeric security level value (2, 3, or 5).
    fn from(level: MLDSA) -> Self { (level as u32).into() }
}

/// Attempts to convert CBOR to an `MLDSA` value.
impl TryFrom<CBOR> for MLDSA {
    type Error = Error;

    /// Converts from a CBOR-encoded security level (2, 3, or 5).
    ///
    /// # Errors
    /// Returns an error if the CBOR value doesn't represent a valid ML-DSA
    /// level.
    fn try_from(cbor: CBOR) -> Result<Self> {
        let level = u32::try_from(cbor)?;
        match level {
            2 => Ok(MLDSA::MLDSA44),
            3 => Ok(MLDSA::MLDSA65),
            5 => Ok(MLDSA::MLDSA87),
            _ => Err(Error::post_quantum(format!("Invalid MLDSA level: {}", level))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_level() {
        let level = MLDSA::MLDSA44;
        assert_eq!(format!("{:?}", level), "MLDSA44");
        let cbor = CBOR::from(level);
        let level2 = MLDSA::try_from(cbor).unwrap();
        assert_eq!(level, level2);

        let level = MLDSA::MLDSA65;
        assert_eq!(format!("{:?}", level), "MLDSA65");
        let cbor = CBOR::from(level);
        let level2 = MLDSA::try_from(cbor).unwrap();
        assert_eq!(level, level2);

        let level = MLDSA::MLDSA87;
        assert_eq!(format!("{:?}", level), "MLDSA87");
        let cbor = CBOR::from(level);
        let level2 = MLDSA::try_from(cbor).unwrap();
        assert_eq!(level, level2);
    }
}
