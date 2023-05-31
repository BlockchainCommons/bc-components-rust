use bc_ur::UREncodable;
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Bytes, Map};

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
    pub fn verify<D1, D2>(&self, signature: D1, message: D2) -> bool
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
    {
        bc_crypto::ecdsa_verify(self, message, signature)
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
        &self.0
    }
}

impl ECKey for ECPublicKey {
    fn public_key(&self) -> ECPublicKey {
        self.clone()
    }
}

impl ECPublicKeyBase for ECPublicKey {
    fn uncompressed_public_key(&self) -> crate::ECUncompressedPublicKey {
        bc_crypto::ecdsa_decompress_public_key(self.data()).into()
    }
}

impl From<[u8; Self::KEY_SIZE]> for ECPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl AsRef<[u8]> for ECPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.data()
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
        m.insert_into(3, Bytes::from_data(self.0));
        m.cbor()
    }
}

impl UREncodable for ECPublicKey { }
