use std::rc::Rc;

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Bytes, CBORDecodable, CBORTaggedDecodable};

use crate::{ECKeyBase, ECKey, tags_registry, ECPublicKeyBase};

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
    fn public_key(&self) -> crate::ECPublicKey {
        bc_crypto::ecdsa_compress_public_key(self.data()).into()
    }
}

impl ECPublicKeyBase for ECUncompressedPublicKey {
    fn compressed(&self) -> crate::ECPublicKey {
        self.public_key()
    }

    fn uncompressed(&self) -> ECUncompressedPublicKey {
        self.clone()
    }
}

impl From<[u8; Self::KEY_SIZE]> for ECUncompressedPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
        Self::from_data(value)
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
        Bytes::from_data(self.0).cbor()
    }
}

impl UREncodable for ECUncompressedPublicKey { }

impl CBORDecodable for ECUncompressedPublicKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for ECUncompressedPublicKey {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(cbor)?;
        let instance = Self::from_data_ref(&bytes.data()).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl URDecodable for ECUncompressedPublicKey { }

impl URCodable for ECUncompressedPublicKey { }
