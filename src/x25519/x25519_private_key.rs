use std::rc::Rc;
use bc_crypto::x25519_new_agreement_private_key_using;
use bc_ur::prelude::*;
use crate::{ tags, Decrypter, EncapsulationPrivateKey, SymmetricKey, X25519PublicKey };
use bc_rand::{ SecureRandomNumberGenerator, RandomNumberGenerator };
use anyhow::{ bail, Error, Result };

/// A Curve25519 private key used for X25519 key agreement.
///
/// <https://datatracker.ietf.org/doc/html/rfc7748>
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct X25519PrivateKey([u8; Self::KEY_SIZE]);

impl X25519PrivateKey {
    pub const KEY_SIZE: usize = 32;

    /// Generate a new random `AgreementPrivateKey`.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Generate a new random `AgreementPrivateKey` and corresponding `AgreementPublicKey`.
    pub fn keypair() -> (X25519PrivateKey, X25519PublicKey) {
        let private_key = X25519PrivateKey::new();
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

    /// Generate a new random `AgreementPrivateKey` using the given random number generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self(x25519_new_agreement_private_key_using(rng))
    }

    /// Restore an `AgreementPrivateKey` from a fixed-size array of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restore an `AgreementPrivateKey` from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid agreement private key size");
        }
        let mut arr = [0u8; Self::KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get a reference to the fixed-size array of bytes.
    pub fn data(&self) -> &[u8; Self::KEY_SIZE] {
        self.into()
    }

    /// Restore an `AgreementPrivateKey` from a hex string.
    ///
    /// # Panics
    ///
    /// Panics if the hex string is invalid or the length is not `AgreementPrivateKey::KEY_SIZE * 2`.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// Get the hex string representation of the `AgreementPrivateKey`.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }

    /// Get the `AgreementPublicKey` corresponding to this `AgreementPrivateKey`.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from_data(
            bc_crypto::x25519_agreement_public_key_from_private_key(self.into())
        )
    }

    /// Derive an `AgreementPrivateKey` from the given key material.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        Self::from_data(bc_crypto::x25519_derive_agreement_private_key(key_material))
    }

    /// Derive a shared symmetric key from this `AgreementPrivateKey` and the given `AgreementPublicKey`.
    pub fn shared_key_with(&self, public_key: &X25519PublicKey) -> SymmetricKey {
        SymmetricKey::from_data(bc_crypto::x25519_shared_key(self.into(), public_key.into()))
    }
}

impl Decrypter for X25519PrivateKey{
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        EncapsulationPrivateKey::X25519(self.clone())
    }
}

impl Default for X25519PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

// Convert from an `AgreementPrivateKey` to a `&'a [u8; AgreementPrivateKey::KEY_SIZE]`.
impl<'a> From<&'a X25519PrivateKey> for &'a [u8; X25519PrivateKey::KEY_SIZE] {
    fn from(value: &'a X25519PrivateKey) -> Self {
        &value.0
    }
}

impl From<Rc<X25519PrivateKey>> for X25519PrivateKey {
    fn from(value: Rc<X25519PrivateKey>) -> Self {
        value.as_ref().clone()
    }
}

impl AsRef<X25519PrivateKey> for X25519PrivateKey {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl CBORTagged for X25519PrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_AGREEMENT_PRIVATE_KEY])
    }
}

impl From<X25519PrivateKey> for CBOR {
    fn from(value: X25519PrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for X25519PrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.data())
    }
}

impl TryFrom<CBOR> for X25519PrivateKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for X25519PrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        Self::from_data_ref(data)
    }
}

impl std::fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgreementPrivateKey({})", self.hex())
    }
}

// Convert from a reference to a byte vector to a AgreementPrivateKey.
impl From<&X25519PrivateKey> for X25519PrivateKey {
    fn from(key: &X25519PrivateKey) -> Self {
        key.clone()
    }
}

// Convert from a byte vector to a AgreementPrivateKey.
impl From<X25519PrivateKey> for Vec<u8> {
    fn from(key: X25519PrivateKey) -> Self {
        key.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a AgreementPrivateKey.
impl From<&X25519PrivateKey> for Vec<u8> {
    fn from(key: &X25519PrivateKey) -> Self {
        key.0.to_vec()
    }
}
