use std::rc::Rc;
use bc_crypto::{RandomNumberGenerator, ecdsa_new_private_key_using};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR, Bytes};
use crate::{tags_registry, ECPrivateKey, Signature};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SigningPrivateKey ([u8; Self::KEY_SIZE]);

impl SigningPrivateKey {
    pub const KEY_SIZE: usize = 32;

    pub fn new() -> Self {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self(ecdsa_new_private_key_using(rng))
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
        self.into()
    }

    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl SigningPrivateKey {
    pub fn ecdsa_sign<T>(&self, message: &T) -> Signature where T: AsRef<[u8]> {
        let private_key = ECPrivateKey::from_data(*self.data());
        let sig = private_key.ecdsa_sign(message);
        Signature::ecdsa_from_data(sig)
    }
}

impl<'a> From<&'a SigningPrivateKey> for &'a [u8; SigningPrivateKey::KEY_SIZE] {
    fn from(value: &'a SigningPrivateKey) -> Self {
        &value.0
    }
}

impl Default for SigningPrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Rc<SigningPrivateKey>> for SigningPrivateKey {
    fn from(value: Rc<SigningPrivateKey>) -> Self {
        value.as_ref().clone()
    }
}

impl CBORTagged for SigningPrivateKey {
    const CBOR_TAG: Tag = tags_registry::AGREEMENT_PRIVATE_KEY;
}

impl CBOREncodable for SigningPrivateKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SigningPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.data()).cbor()
    }
}

impl CBORDecodable for SigningPrivateKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SigningPrivateKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(untagged_cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl UREncodable for SigningPrivateKey { }

impl URDecodable for SigningPrivateKey { }

impl URCodable for SigningPrivateKey { }

impl std::fmt::Debug for SigningPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningPrivateKey")
    }
}

// Convert from a reference to a byte vector to a SigningPrivateKey.
impl From<&SigningPrivateKey> for SigningPrivateKey {
    fn from(key: &SigningPrivateKey) -> Self {
        key.clone()
    }
}

// Convert from a byte vector to a SigningPrivateKey.
impl From<SigningPrivateKey> for Vec<u8> {
    fn from(key: SigningPrivateKey) -> Self {
        key.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a SigningPrivateKey.
impl From<&SigningPrivateKey> for Vec<u8> {
    fn from(key: &SigningPrivateKey) -> Self {
        key.0.to_vec()
    }
}
