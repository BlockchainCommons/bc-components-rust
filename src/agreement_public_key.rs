use std::rc::Rc;
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR, Bytes};
use crate::tags_registry;

/// A Curve25519 public key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgreementPublicKey ([u8; Self::KEY_SIZE]);

impl AgreementPublicKey {
    pub const KEY_SIZE: usize = 32;

    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }

    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::KEY_SIZE];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    pub fn data(&self) -> &[u8; Self::KEY_SIZE] {
        self.into()
    }

    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl From<Rc<AgreementPublicKey>> for AgreementPublicKey {
    fn from(value: Rc<AgreementPublicKey>) -> Self {
        value.as_ref().clone()
    }
}

impl<'a> From<&'a AgreementPublicKey> for &'a [u8; AgreementPublicKey::KEY_SIZE] {
    fn from(value: &'a AgreementPublicKey) -> Self {
        &value.0
    }
}

impl CBORTagged for AgreementPublicKey {
    const CBOR_TAG: Tag = tags_registry::AGREEMENT_PUBLIC_KEY;
}

impl CBOREncodable for AgreementPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for AgreementPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.data()).cbor()
    }
}

impl CBORDecodable for AgreementPublicKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for AgreementPublicKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(untagged_cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl UREncodable for AgreementPublicKey { }

impl URDecodable for AgreementPublicKey { }

impl URCodable for AgreementPublicKey { }

impl std::fmt::Debug for AgreementPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgreementPublicKey({})", self.hex())
    }
}

// Convert from a reference to a byte vector to a AgreementPublicKey.
impl From<&AgreementPublicKey> for AgreementPublicKey {
    fn from(key: &AgreementPublicKey) -> Self {
        key.clone()
    }
}

// Convert from a byte vector to a AgreementPublicKey.
impl From<AgreementPublicKey> for Vec<u8> {
    fn from(key: AgreementPublicKey) -> Self {
        key.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a AgreementPublicKey.
impl From<&AgreementPublicKey> for Vec<u8> {
    fn from(key: &AgreementPublicKey) -> Self {
        key.0.to_vec()
    }
}
