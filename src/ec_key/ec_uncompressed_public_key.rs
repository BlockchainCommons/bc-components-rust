use crate::ECKeyBaseTrait;

use super::{ec_key_trait::ECKeyTrait, ec_public_key_trait::ECPublicKeyTrait};


pub struct ECUncompressedPublicKey([u8; Self::KEY_LENGTH]);

impl ECUncompressedPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_LENGTH]) -> Self {
        Self(data)
    }
}

impl ECKeyBaseTrait for ECUncompressedPublicKey {
    const KEY_LENGTH: usize = bc_crypto::ECDSA_PUBLIC_KEY_LENGTH_UNCOMPRESSED;

    fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]>, Self: Sized {
        let data = data.as_ref();
        if data.len() != Self::KEY_LENGTH {
            return None;
        }
        let mut key = [0u8; Self::KEY_LENGTH];
        key.copy_from_slice(data);
        Some(Self(key))
    }
}

impl ECKeyTrait for ECUncompressedPublicKey {
    // ...
}

impl ECPublicKeyTrait for ECUncompressedPublicKey {
    // ...
}
