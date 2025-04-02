use anyhow::{bail, Result};

pub const ED25519_PUBLIC_KEY_SIZE: usize = bc_crypto::ED25519_PUBLIC_KEY_SIZE;

/// An Ed25519 public key for verifying digital signatures.
///
/// Ed25519 public keys are used to verify signatures created with the corresponding
/// private key. The Ed25519 signature system provides:
///
/// - Fast signature verification
/// - Small public keys (32 bytes)
/// - High security with resistance to various attacks
///
/// This implementation allows:
/// - Creating Ed25519 public keys from raw data
/// - Verifying signatures against messages
/// - Converting between various formats
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_SIZE]);

impl Ed25519PublicKey {
    /// Restores an Ed25519 public key from an array of bytes.
    pub const fn from_data(data: [u8; ED25519_PUBLIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ED25519_PUBLIC_KEY_SIZE {
            bail!("Invalid Ed25519 public key size");
        }
        let mut key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    /// Returns the Ed25519 public key as an array of bytes.
    pub fn data(&self) -> &[u8; ED25519_PUBLIC_KEY_SIZE] {
        &self.0
    }

    fn hex(&self) -> String {
        hex::encode(self.data())
    }

    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self> {
        let data = hex::decode(hex.as_ref())?;
        Self::from_data_ref(data)
    }
}

impl Ed25519PublicKey {
    /// Verifies the given Ed25519 signature for the given message using this Ed25519 public key.
    pub fn verify(&self, signature: &[u8; bc_crypto::ED25519_SIGNATURE_SIZE], message: impl AsRef<[u8]>) -> bool {
        bc_crypto::ed25519_verify(&self.0, message.as_ref(), signature)
    }
}

/// Implements Display to output the key as a hex string.
impl std::fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

/// Implements Debug to output the key with a type label.
impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PublicKey({})", self.hex())
    }
}

/// Implements conversion from an Ed25519PublicKey reference to a byte array reference.
impl<'a> From<&'a Ed25519PublicKey> for &'a [u8; ED25519_PUBLIC_KEY_SIZE] {
    fn from(value: &'a Ed25519PublicKey) -> Self {
        &value.0
    }
}

/// Implements conversion from a byte array to an Ed25519PublicKey.
impl From<[u8; ED25519_PUBLIC_KEY_SIZE]> for Ed25519PublicKey {
    fn from(value: [u8; ED25519_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

/// Implements conversion from an Ed25519PublicKey reference to a byte slice.
impl<'a> From<&'a Ed25519PublicKey> for &'a [u8] {
    fn from(value: &'a Ed25519PublicKey) -> Self {
        &value.0
    }
}
