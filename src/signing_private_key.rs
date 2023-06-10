use std::rc::Rc;
use bc_crypto::{RandomNumberGenerator, ecdsa_new_private_key_using};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR};
use crate::{tags, ECPrivateKey, Signature, ECKey, SigningPublicKey};

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

    pub fn ecdsa_public_key(&self) -> SigningPublicKey {
        SigningPublicKey::from_ecdsa(ECPrivateKey::from_data(*self.data()).public_key())
    }

    pub fn schnorr_public_key(&self) -> SigningPublicKey {
        SigningPublicKey::from_schnorr(ECPrivateKey::from_data(*self.data()).schnorr_public_key())
    }

    pub fn derive_from_key_material<D>(key_material: D) -> Self
        where D: AsRef<[u8]>
    {
        Self::from_data(bc_crypto::x25519_derive_signing_private_key(key_material))
    }
}

impl SigningPrivateKey {
    pub fn ecdsa_sign<T>(&self, message: &T) -> Signature where T: AsRef<[u8]> {
        let private_key = ECPrivateKey::from_data(*self.data());
        let sig = private_key.ecdsa_sign(message);
        Signature::ecdsa_from_data(sig)
    }

    pub fn schnorr_sign_using<D1, D2>(
        &self,
        message: D1,
        tag: D2,
        rng: &mut impl bc_crypto::RandomNumberGenerator
    ) -> Signature
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
    {
        // let tag = tag.into();
        let private_key = ECPrivateKey::from_data(*self.data());
        let tag_copy = tag.as_ref().to_vec();
        let sig = private_key.schnorr_sign_using(message, tag, rng);
        Signature::schnorr_from_data(sig, tag_copy)
    }

    pub fn schnorr_sign<D1, D2>(
        &self,
        message: D1,
        tag: D2,
    ) -> Signature
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
    {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        self.schnorr_sign_using(message, tag, &mut rng)
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
    const CBOR_TAG: Tag = tags::SIGNING_PRIVATE_KEY;
}

impl CBOREncodable for SigningPrivateKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SigningPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.data())
    }
}

impl CBORDecodable for SigningPrivateKey {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SigningPrivateKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(instance)
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
