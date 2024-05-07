use crate::{EncryptedMessage, Nonce, tags, Digest};
use bc_crypto::{aead_chacha20_poly1305_encrypt_with_aad, aead_chacha20_poly1305_decrypt_with_aad};
use bc_ur::prelude::*;
use anyhow::{bail, Result, Error};
use bytes::Bytes;

/// A symmetric encryption key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SymmetricKey([u8; Self::SYMMETRIC_KEY_SIZE]);

impl SymmetricKey {
    pub const SYMMETRIC_KEY_SIZE: usize = 32;

    /// Create a new random symmetric key.
    pub fn new() -> Self {
        let mut rng = bc_rand::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Create a new random symmetric key using the given random number generator.
    pub fn new_using(rng: &mut impl bc_rand::RandomNumberGenerator) -> Self {
        let mut key = [0u8; Self::SYMMETRIC_KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Create a new symmetric key from data.
    pub const fn from_data(data: [u8; Self::SYMMETRIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new symmetric key from data.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::SYMMETRIC_KEY_SIZE {
            bail!("Invalid symmetric key size");
        }
        let mut arr = [0u8; Self::SYMMETRIC_KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get the data of the symmetric key.
    pub fn data(&self) -> &[u8; Self::SYMMETRIC_KEY_SIZE] {
        self.into()
    }

    /// Create a new symmetric key from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 24 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self> {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap())
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }

    /// Encrypt the given plaintext with this key, and the given additional authenticated data and nonce.
    pub fn encrypt(&self, plaintext: impl Into<Bytes>, aad: Option<impl Into<Bytes>>, nonce: Option<impl AsRef<Nonce>>) -> EncryptedMessage
    {
        let aad: Bytes = aad.map(|a| a.into()).unwrap_or_default();
        let nonce: Nonce = nonce.map(|n| n.as_ref().clone()).unwrap_or_default();
        let plaintext = plaintext.into();
        let (ciphertext, auth) = aead_chacha20_poly1305_encrypt_with_aad(plaintext, self.into(), (&nonce).into(), &aad);
        EncryptedMessage::new(Bytes::from(ciphertext), aad, nonce, auth.into())
    }

    /// Encrypt the given plaintext with this key, and the given digest of the plaintext, and nonce.
    pub fn encrypt_with_digest(&self, plaintext: impl Into<Bytes>, digest: impl AsRef<Digest>, nonce: Option<impl AsRef<Nonce>>) -> EncryptedMessage
    {
        let cbor: CBOR = digest.as_ref().clone().into();
        let data = cbor.to_cbor_data();
        self.encrypt(plaintext, Some(Bytes::from(data)), nonce)
    }

    /// Decrypt the given encrypted message with this key.
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>, bc_crypto::Error> {
        aead_chacha20_poly1305_decrypt_with_aad(message.ciphertext(), self.into(), message.nonce().into(), message.aad(), message.authentication_tag().into())
    }
}

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<SymmetricKey> for SymmetricKey {
    fn as_ref(&self) -> &SymmetricKey {
        self
    }
}

impl<'a> From<&'a SymmetricKey> for &'a [u8; SymmetricKey::SYMMETRIC_KEY_SIZE] {
    fn from(digest: &'a SymmetricKey) -> Self {
        &digest.0
    }
}

// Convert from a reference to a byte vector to an instance.
impl From<&SymmetricKey> for SymmetricKey {
    fn from(digest: &SymmetricKey) -> Self {
        digest.clone()
    }
}

// Convert from a byte vector to an instance.
impl From<SymmetricKey> for Vec<u8> {
    fn from(digest: SymmetricKey) -> Self {
        digest.0.to_vec()
    }
}

// Convert a reference to an instance to a byte vector.
impl From<&SymmetricKey> for Vec<u8> {
    fn from(digest: &SymmetricKey) -> Self {
        digest.0.to_vec()
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey({})", self.hex())
    }
}

impl CBORTagged for SymmetricKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SYMMETRIC_KEY]
    }
}

impl From<SymmetricKey> for CBOR {
    fn from(value: SymmetricKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SymmetricKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.0)
    }
}

impl TryFrom<CBOR> for SymmetricKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SymmetricKey {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        let bytes = CBOR::try_into_byte_string(cbor)?;
        let instance = Self::from_data_ref(&bytes)?;
        Ok(instance)
    }
}
