use crate::ECKeyBaseTrait;


#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SchnorrPublicKey([u8; Self::KEY_SIZE]);

impl SchnorrPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
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

impl ECKeyBaseTrait for SchnorrPublicKey {
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
