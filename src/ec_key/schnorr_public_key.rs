use anyhow::{bail, Result};
use bc_crypto::SCHNORR_SIGNATURE_SIZE;

use crate::ECKeyBase;

pub const SCHNORR_PUBLIC_KEY_SIZE: usize = bc_crypto::SCHNORR_PUBLIC_KEY_SIZE;

/// A Schnorr (x-only) elliptic curve public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SchnorrPublicKey([u8; SCHNORR_PUBLIC_KEY_SIZE]);

impl SchnorrPublicKey {
    /// Restores a Schnorr public key from an array of bytes.
    pub const fn from_data(data: [u8; SCHNORR_PUBLIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Returns the Schnorr public key from an array of bytes.
    pub fn data(&self) -> &[u8; SCHNORR_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl SchnorrPublicKey {
    /// Verifies the given Schnorr signature for the given message and tag.
    pub fn schnorr_verify(&self, signature: &[u8; SCHNORR_SIGNATURE_SIZE],  message: impl AsRef<[u8]>) -> bool {
        bc_crypto::schnorr_verify(self.into(), signature, message)
    }
}

impl<'a> From<&'a SchnorrPublicKey> for &'a [u8; SchnorrPublicKey::KEY_SIZE] {
    fn from(value: &'a SchnorrPublicKey) -> Self {
        &value.0
    }
}

impl From<[u8; SCHNORR_PUBLIC_KEY_SIZE]> for SchnorrPublicKey {
    fn from(value: [u8; SCHNORR_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl AsRef<[u8]> for SchnorrPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl std::fmt::Display for SchnorrPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for SchnorrPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SchnorrPublicKey({})", self.hex())
    }
}

impl ECKeyBase for SchnorrPublicKey {
    const KEY_SIZE: usize = bc_crypto::SCHNORR_PUBLIC_KEY_SIZE;

    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != SCHNORR_PUBLIC_KEY_SIZE {
            bail!("invalid Schnorr public key size");
        }
        let mut key = [0u8; SCHNORR_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    fn data(&self) -> &[u8] {
        &self.0
    }
}
