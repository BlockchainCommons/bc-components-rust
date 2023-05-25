use std::rc::Rc;
use crate::{EncryptedMessage, Nonce, tags_registry};
use bc_crypto::{encrypt_aead_chacha20_poly1305_with_aad, decrypt_aead_chacha20_poly1305_with_aad, fill_random_data, CryptoError};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBORTaggedEncodable, CBOR, CBOREncodable, Bytes, CBORDecodable, CBORError, CBORTaggedDecodable};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SymmetricKey([u8; Self::SYMMETRIC_KEY_LENGTH]);

impl SymmetricKey {
    pub const SYMMETRIC_KEY_LENGTH: usize = 12;

    /// Create a new random symmetric key.
    pub fn new() -> Self {
        let mut key = [0u8; Self::SYMMETRIC_KEY_LENGTH];
        fill_random_data(&mut key);
        Self(key)
    }

    /// Create a new symmetric key from data.
    pub fn from_data(data: [u8; Self::SYMMETRIC_KEY_LENGTH]) -> Self {
        Self(data)
    }

    /// Create a new symmetric key from data.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::SYMMETRIC_KEY_LENGTH {
            return None;
        }
        let mut arr = [0u8; Self::SYMMETRIC_KEY_LENGTH];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Get the data of the symmetric key.
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    /// Create a new symmetric key from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 24 hexadecimal digits.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }

    /// Encrypt the given plaintext with this key, and the given additional authenticated data and nonce.
    pub fn encrypt_with_nonce<D, A>(&self, plaintext: D, aad: A, nonce: Nonce) -> EncryptedMessage
    where
        D: AsRef<[u8]>,
        A: Into<Vec<u8>>,
    {
        let aad: Vec<u8> = aad.into();
        let (ciphertext, auth) = encrypt_aead_chacha20_poly1305_with_aad(plaintext, self, &nonce, &aad);
        EncryptedMessage::new(ciphertext, aad, nonce, auth.into())
    }

    /// Encrypt the given plaintext with this key, and the given additional authenticated data and a random nonce.
    pub fn encrypt<D, A>(&self, plaintext: D, aad: A) -> EncryptedMessage
    where
        D: AsRef<[u8]>,
        A: Into<Vec<u8>>,
    {
        self.encrypt_with_nonce(plaintext, aad, Nonce::new())
    }

    /// Decrypt the given encrypted message with this key.
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>, CryptoError> {
        decrypt_aead_chacha20_poly1305_with_aad(message.ciphertext(), self, message.nonce(), message.aad(), message.auth())
    }
}

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

// Convert from a SymmetricKey to a reference to a byte array.
impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

impl std::fmt::Display for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey({})", self.hex())
    }
}

impl CBORTagged for SymmetricKey {
    const CBOR_TAG: Tag = tags_registry::SYMMETRIC_KEY;
}

impl CBOREncodable for SymmetricKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SymmetricKey {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.0).cbor()
    }
}

impl UREncodable for SymmetricKey { }

impl CBORDecodable for SymmetricKey {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SymmetricKey {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = Bytes::from_cbor(cbor)?;
        let instance = Self::from_data_ref(&bytes.data()).ok_or(CBORError::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl URDecodable for SymmetricKey { }

impl URCodable for SymmetricKey { }
