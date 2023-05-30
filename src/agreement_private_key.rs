use std::rc::Rc;
use bc_crypto::{RandomNumberGenerator, x25519_new_agreement_private_key, x25519_new_agreement_private_key_using};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR, Bytes};
use crate::tags_registry;

/// A Curve25519 private key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgreementPrivateKey ([u8; Self::KEY_SIZE]);

impl AgreementPrivateKey {
    pub const KEY_SIZE: usize = 32;

    pub fn new() -> Self {
        Self(x25519_new_agreement_private_key())
    }

    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self(x25519_new_agreement_private_key_using(rng))
    }

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
        &self.0
    }

    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl Default for AgreementPrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Rc<AgreementPrivateKey>> for AgreementPrivateKey {
    fn from(value: Rc<AgreementPrivateKey>) -> Self {
        value.as_ref().clone()
    }
}

impl AsRef<[u8]> for AgreementPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CBORTagged for AgreementPrivateKey {
    const CBOR_TAG: Tag = tags_registry::AGREEMENT_PRIVATE_KEY;
}

impl CBOREncodable for AgreementPrivateKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for AgreementPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.data()).cbor()
    }
}

impl CBORDecodable for AgreementPrivateKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for AgreementPrivateKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(untagged_cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl std::fmt::Debug for AgreementPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgreementPrivateKey({})", self.hex())
    }
}

// Convert from a reference to a byte vector to a AgreementPrivateKey.
impl From<&AgreementPrivateKey> for AgreementPrivateKey {
    fn from(key: &AgreementPrivateKey) -> Self {
        key.clone()
    }
}

// Convert from a byte vector to a AgreementPrivateKey.
impl From<AgreementPrivateKey> for Vec<u8> {
    fn from(key: AgreementPrivateKey) -> Self {
        key.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a AgreementPrivateKey.
impl From<&AgreementPrivateKey> for Vec<u8> {
    fn from(key: &AgreementPrivateKey) -> Self {
        key.0.to_vec()
    }
}
