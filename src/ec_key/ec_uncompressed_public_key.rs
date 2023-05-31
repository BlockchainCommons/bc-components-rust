use bc_ur::UREncodable;
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Bytes, Map};

use crate::{ECKeyBase, ECKey, tags_registry, ECPublicKeyBase, ECPublicKey};

/// An uncompressed elliptic curve public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECUncompressedPublicKey([u8; Self::KEY_SIZE]);

impl ECUncompressedPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl std::fmt::Display for ECUncompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for ECUncompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECUncompressedPublicKey({})", self.hex())
    }
}

impl ECKeyBase for ECUncompressedPublicKey {
    const KEY_SIZE: usize = bc_crypto::ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE;

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

impl ECKey for ECUncompressedPublicKey {
    fn public_key(&self) -> ECPublicKey {
        bc_crypto::ecdsa_compress_public_key(self.data()).into()
    }
}

impl ECPublicKeyBase for ECUncompressedPublicKey {
    fn uncompressed_public_key(&self) -> ECUncompressedPublicKey {
        self.clone()
    }
}

impl From<[u8; Self::KEY_SIZE]> for ECUncompressedPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl AsRef<[u8]> for ECUncompressedPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl CBORTagged for ECUncompressedPublicKey {
    const CBOR_TAG: Tag = tags_registry::EC_KEY;
}

impl CBOREncodable for ECUncompressedPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ECUncompressedPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert_into(3, Bytes::from_data(self.0));
        m.cbor()
    }
}

impl UREncodable for ECUncompressedPublicKey { }
