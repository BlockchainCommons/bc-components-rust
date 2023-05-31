use std::rc::Rc;

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Bytes, CBORDecodable, CBORTaggedDecodable};

use crate::{ECKeyBase, ECKey, tags_registry};

/// An elliptic curve private key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPrivateKey([u8; Self::KEY_SIZE]);

impl ECPrivateKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl std::fmt::Display for ECPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for ECPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPrivateKey({})", self.hex())
    }
}

impl ECKeyBase for ECPrivateKey {
    const KEY_SIZE: usize = bc_crypto::ECDSA_PRIVATE_KEY_SIZE;

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

impl ECKey for ECPrivateKey {
    fn public_key(&self) -> crate::ECPublicKey {
        bc_crypto::ecdsa_public_key_from_private_key(self.data()).into()
    }
}

impl CBORTagged for ECPrivateKey {
    const CBOR_TAG: Tag = tags_registry::EC_KEY;
}

impl CBOREncodable for ECPrivateKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ECPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.0).cbor()
    }
}

impl UREncodable for ECPrivateKey { }

impl CBORDecodable for ECPrivateKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for ECPrivateKey {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(cbor)?;
        let instance = Self::from_data_ref(&bytes.data()).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl URDecodable for ECPrivateKey { }

impl URCodable for ECPrivateKey { }
