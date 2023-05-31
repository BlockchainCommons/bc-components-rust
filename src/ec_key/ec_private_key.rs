use bc_ur::UREncodable;
use dcbor::{Tag, CBORTagged, CBOREncodable, CBOR, CBORTaggedEncodable, Bytes, Map};

use crate::{ECKeyBase, ECKey, tags_registry, SchnorrPublicKey, ECPublicKey};

/// An elliptic curve private key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPrivateKey([u8; Self::KEY_SIZE]);

impl ECPrivateKey {
    pub fn new() -> Self {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    pub fn new_using(rng: &mut impl bc_crypto::RandomNumberGenerator) -> Self {
        let mut key = [0u8; Self::KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl ECPrivateKey {
    pub fn schnorr_public_key(&self) -> SchnorrPublicKey {
        bc_crypto::schnorr_public_key_from_private_key(self.into()).into()
    }

    pub fn ecdsa_sign<T>(&self, message: &T) -> [u8; bc_crypto::ECDSA_SIGNATURE_SIZE] where T: AsRef<[u8]> {
        bc_crypto::ecdsa_sign(&self.0, message.as_ref())
    }

    pub fn schnorr_sign_using<D1, D2>(
        &self,
        message: &D1,
        tag: &D2,
        rng: &mut impl bc_crypto::RandomNumberGenerator
    ) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE]
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>
    {
        bc_crypto::schnorr_sign_using(message, tag, &self.0, rng)
    }

    pub fn schnorr_sign<D1, D2>(&self, message: &D1, tag: &D2) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE]
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>
    {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        self.schnorr_sign_using(message, tag, &mut rng)
    }
}

impl From<[u8; 32]> for ECPrivateKey {
    fn from(data: [u8; 32]) -> Self {
        Self::from_data(data)
    }
}

impl AsRef<[u8]> for ECPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.data()
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

impl Default for ECPrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a ECPrivateKey> for &'a [u8; ECPrivateKey::KEY_SIZE] {
    fn from(value: &'a ECPrivateKey) -> Self {
        &value.0
    }
}

impl<'a> From<&'a ECPrivateKey> for &'a [u8] {
    fn from(value: &'a ECPrivateKey) -> Self {
        value.as_ref()
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
        self.into()
    }
}

impl ECKey for ECPrivateKey {
    fn public_key(&self) -> ECPublicKey {
        bc_crypto::ecdsa_public_key_from_private_key(&self.0).into()
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
        let mut m = Map::new();
        m.insert_into(2, true);
        m.insert_into(3, Bytes::from_data(self.0));
        m.cbor()
    }
}

impl UREncodable for ECPrivateKey { }
