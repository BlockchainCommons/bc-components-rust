use bc_crypto::SCHNORR_SIGNATURE_SIZE;

use crate::ECKeyBase;


/// A Schnorr (x-only) elliptic curve public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SchnorrPublicKey([u8; Self::KEY_SIZE]);

impl SchnorrPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl SchnorrPublicKey {
    pub fn schnorr_verify<D1, D2>(&self, signature: &[u8; SCHNORR_SIGNATURE_SIZE],  message: D1, tag: D2) -> bool
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>
    {
        bc_crypto::schnorr_verify(self.into(), signature, message, tag)
    }
}

impl<'a> From<&'a SchnorrPublicKey> for &'a [u8; SchnorrPublicKey::KEY_SIZE] {
    fn from(value: &'a SchnorrPublicKey) -> Self {
        &value.0
    }
}

impl From<[u8; Self::KEY_SIZE]> for SchnorrPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
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

    fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            return None;
        }
        let mut key = [0u8; Self::KEY_SIZE];
        key.copy_from_slice(data);
        Some(Self(key))
    }

    fn data(&self) -> &[u8] {
        &self.0
    }
}
