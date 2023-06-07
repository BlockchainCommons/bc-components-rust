use crate::{EncryptedMessage, Nonce, tags_registry, Digest};
use bc_crypto::{encrypt_aead_chacha20_poly1305_with_aad, decrypt_aead_chacha20_poly1305_with_aad};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBORTaggedEncodable, CBOR, CBOREncodable, CBORDecodable, CBORTaggedDecodable};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SymmetricKey([u8; Self::SYMMETRIC_KEY_SIZE]);

impl SymmetricKey {
    pub const SYMMETRIC_KEY_SIZE: usize = 32;

    /// Create a new random symmetric key.
    pub fn new() -> Self {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Create a new random symmetric key using the given random number generator.
    pub fn new_using(rng: &mut impl bc_crypto::RandomNumberGenerator) -> Self {
        let mut key = [0u8; Self::SYMMETRIC_KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Create a new symmetric key from data.
    pub const fn from_data(data: [u8; Self::SYMMETRIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new symmetric key from data.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::SYMMETRIC_KEY_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::SYMMETRIC_KEY_SIZE];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Get the data of the symmetric key.
    pub fn data(&self) -> &[u8; Self::SYMMETRIC_KEY_SIZE] {
        self.into()
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
    pub fn encrypt<D, N>(&self, plaintext: D, aad: Option<&[u8]>, nonce: Option<N>) -> EncryptedMessage
    where
        D: AsRef<[u8]>,
        N: AsRef<Nonce>
    {
        let aad = aad.unwrap_or(&[]).into();
        let nonce: Nonce = nonce.map(|n| n.as_ref().clone()).unwrap_or_else(Nonce::new);
        let (ciphertext, auth) = encrypt_aead_chacha20_poly1305_with_aad(plaintext, self.into(), (&nonce).into(), &aad);
        EncryptedMessage::new(ciphertext, aad, nonce, auth.into())
    }

    /// Encrypt the given plaintext with this key, and the given digest of the plaintext, and nonce.
    pub fn encrypt_with_digest<D, N>(&self, plaintext: D, digest: &Digest, nonce: Option<N>) -> EncryptedMessage
    where
        D: AsRef<[u8]>,
        N: AsRef<Nonce>,
    {
        self.encrypt(plaintext, Some(&digest.cbor_data()), nonce)
    }

    /// Decrypt the given encrypted message with this key.
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>, bc_crypto::Error> {
        decrypt_aead_chacha20_poly1305_with_aad(message.ciphertext(), self.into(), message.nonce().into(), message.aad(), message.auth().into())
    }
}

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
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
    const CBOR_TAG: Tag = tags_registry::SYMMETRIC_KEY;
}

impl CBOREncodable for SymmetricKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SymmetricKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.0)
    }
}

impl UREncodable for SymmetricKey { }

impl CBORDecodable for SymmetricKey {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SymmetricKey {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let bytes = CBOR::expect_byte_string(cbor)?;
        let instance = Self::from_data_ref(&bytes).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(instance)
    }
}

impl URDecodable for SymmetricKey { }

impl URCodable for SymmetricKey { }
