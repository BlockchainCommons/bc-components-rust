use bc_crypto::ECDSA_SIGNATURE_SIZE;
use bc_ur::UREncodable;
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Map, bstring};

use crate::{ECKeyBase, ECKey, ECPublicKeyBase, tags_registry};

/// A compressed elliptic curve public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPublicKey([u8; Self::KEY_SIZE]);

impl ECPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl ECPublicKey {
    pub fn verify<D>(&self, signature: &[u8; ECDSA_SIGNATURE_SIZE], message: D) -> bool
    where
        D: AsRef<[u8]>,
    {
        bc_crypto::ecdsa_verify(&self.0, signature, message)
    }
}

impl std::fmt::Display for ECPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for ECPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPublicKey({})", self.hex())
    }
}

impl ECKeyBase for ECPublicKey {
    const KEY_SIZE: usize = bc_crypto::ECDSA_PUBLIC_KEY_SIZE;

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
        self.into()
    }
}

impl ECKey for ECPublicKey {
    fn public_key(&self) -> ECPublicKey {
        self.clone()
    }
}

impl ECPublicKeyBase for ECPublicKey {
    fn uncompressed_public_key(&self) -> crate::ECUncompressedPublicKey {
        bc_crypto::ecdsa_decompress_public_key(&self.0).into()
    }
}

impl<'a> From<&'a ECPublicKey> for &'a [u8; ECPublicKey::KEY_SIZE] {
    fn from(value: &'a ECPublicKey) -> Self {
        &value.0
    }
}

impl From<[u8; Self::KEY_SIZE]> for ECPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl<'a> From<&'a ECPublicKey> for &'a [u8] {
    fn from(value: &'a ECPublicKey) -> Self {
        &value.0
    }
}

impl CBORTagged for ECPublicKey {
    const CBOR_TAG: Tag = tags_registry::EC_KEY;
}

impl CBOREncodable for ECPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ECPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert_into(3, bstring(self.0));
        m.cbor()
    }
}

impl UREncodable for ECPublicKey { }
