use std::rc::Rc;

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Bytes, CBORDecodable, CBORTaggedDecodable};

use crate::{ECKeyBase, ECKey, ECPublicKeyBase, tags_registry};

/// A compressed elliptic curve public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPublicKey([u8; Self::KEY_SIZE]);

impl ECPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
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
        Bytes::from_data(self.0).cbor()
    }
}

impl UREncodable for ECPublicKey { }

impl CBORDecodable for ECPublicKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for ECPublicKey {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(cbor)?;
        let instance = Self::from_data_ref(&bytes.data()).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl URDecodable for ECPublicKey { }

impl URCodable for ECPublicKey { }
