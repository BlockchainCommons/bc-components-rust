use std::rc::Rc;
use bc_crypto::{RandomNumberGenerator, x25519_new_agreement_private_key_using};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR};
use crate::{tags, AgreementPublicKey, SymmetricKey};

/// A Curve25519 private key used for X25519 key agreement.
///
/// <https://datatracker.ietf.org/doc/html/rfc7748>
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgreementPrivateKey ([u8; Self::KEY_SIZE]);

impl AgreementPrivateKey {
    pub const KEY_SIZE: usize = 32;

    pub fn new() -> Self {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
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
        self.into()
    }

    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }

    pub fn public_key(&self) -> AgreementPublicKey {
        AgreementPublicKey::from_data(bc_crypto::x25519_agreement_public_key_from_private_key(self.into()))
    }

    pub fn derive_from_key_material<D>(key_material: D) -> Self
        where D: AsRef<[u8]>
    {
        Self::from_data(bc_crypto::x25519_derive_agreement_private_key(key_material))
    }

    pub fn shared_key_with(&self, public_key: &AgreementPublicKey) -> SymmetricKey {
        SymmetricKey::from_data(bc_crypto::x25519_shared_key(self.into(), public_key.into()))
    }
}

impl Default for AgreementPrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

// Convert from an `AgreementPrivateKey` to a `&'a [u8; AgreementPrivateKey::KEY_SIZE]`.
impl<'a> From<&'a AgreementPrivateKey> for &'a [u8; AgreementPrivateKey::KEY_SIZE] {
    fn from(value: &'a AgreementPrivateKey) -> Self {
        &value.0
    }
}

impl From<Rc<AgreementPrivateKey>> for AgreementPrivateKey {
    fn from(value: Rc<AgreementPrivateKey>) -> Self {
        value.as_ref().clone()
    }
}

impl CBORTagged for AgreementPrivateKey {
    const CBOR_TAG: Tag = tags::AGREEMENT_PRIVATE_KEY;
}

impl CBOREncodable for AgreementPrivateKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for AgreementPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.data())
    }
}

impl CBORDecodable for AgreementPrivateKey {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for AgreementPrivateKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(instance)
    }
}

impl UREncodable for AgreementPrivateKey { }

impl URDecodable for AgreementPrivateKey { }

impl URCodable for AgreementPrivateKey { }

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
