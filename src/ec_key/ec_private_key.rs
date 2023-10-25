use anyhow::bail;
use bc_ur::prelude::*;

use crate::{ECKeyBase, ECKey, tags, SchnorrPublicKey, ECPublicKey};

/// An elliptic curve digital signature algorithm (ECDSA) private key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPrivateKey([u8; Self::KEY_SIZE]);

impl ECPrivateKey {
    /// Creates a new random ECDSA private key.
    pub fn new() -> Self {
        let mut rng = bc_rand::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Creates a new random ECDSA private key using the given random number generator.
    pub fn new_using(rng: &mut impl bc_rand::RandomNumberGenerator) -> Self {
        let mut key = [0u8; Self::KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Restores an ECDSA private key from a vector of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl ECPrivateKey {
    /// Derives the Schnorr public key from this ECDSA private key.
    pub fn schnorr_public_key(&self) -> SchnorrPublicKey {
        bc_crypto::schnorr_public_key_from_private_key(self.into()).into()
    }

    /// ECDSA signs the given message using this ECDSA private key.
    pub fn ecdsa_sign(&self, message: impl AsRef<[u8]>) -> [u8; bc_crypto::ECDSA_SIGNATURE_SIZE] {
        bc_crypto::ecdsa_sign(&self.0, message.as_ref())
    }

    /// Schnorr signs the given message using this ECDSA private key, the given
    /// tag, and the given random number generator.
    pub fn schnorr_sign_using<D1, D2>(
        &self,
        message: D1,
        tag: D2,
        rng: &mut impl bc_rand::RandomNumberGenerator
    ) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE]
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>
    {
        bc_crypto::schnorr_sign_using(&self.0, message, tag, rng)
    }

    /// Schnorr signs the given message using this ECDSA private key and the given tag.
    pub fn schnorr_sign<D1, D2>(&self, message: D1, tag: D2) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE]
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>
    {
        let mut rng = bc_rand::SecureRandomNumberGenerator;
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

    fn from_data_ref(data: impl AsRef<[u8]>) -> anyhow::Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid EC private key size");
        }
        let mut key = [0u8; Self::KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
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
    const CBOR_TAG: Tag = tags::EC_KEY;
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
        m.insert_into(3, CBOR::byte_string(self.0));
        m.cbor()
    }
}

impl UREncodable for ECPrivateKey { }
