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
    pub fn schnorr_verify<D1, D2, D3>(&self, signature: D1, tag: D2, message: D3) -> bool
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
        D3: AsRef<[u8]>
    {
        bc_crypto::schnorr_verify(message, tag, signature, self)
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

    fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]>, Self: Sized {
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
