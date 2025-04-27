use crate::{ EncryptedMessage, Nonce, tags, Digest };
use bc_crypto::{ aead_chacha20_poly1305_encrypt_with_aad, aead_chacha20_poly1305_decrypt_with_aad };
use bc_ur::prelude::*;
use anyhow::{ bail, Result, Error };

/// A symmetric encryption key used for both encryption and decryption.
///
/// `SymmetricKey` is a 32-byte cryptographic key used with ChaCha20-Poly1305 AEAD
/// (Authenticated Encryption with Associated Data) encryption. This implementation follows
/// the IETF ChaCha20-Poly1305 specification as defined in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
///
/// Symmetric encryption uses the same key for both encryption and decryption, unlike
/// asymmetric encryption where different keys are used for each operation.
///
/// `SymmetricKey` can be used to encrypt plaintext into an `EncryptedMessage` that includes:
/// - Ciphertext (the encrypted data)
/// - Nonce (a unique number used once for each encryption)
/// - Authentication tag (to verify message integrity)
/// - Optional additional authenticated data (AAD)
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
    pub fn encrypt(
        &self,
        plaintext: impl Into<Vec<u8>>,
        aad: Option<impl Into<Vec<u8>>>,
        nonce: Option<impl AsRef<Nonce>>
    ) -> EncryptedMessage {
        let aad: Vec<u8> = aad.map(|a| a.into()).unwrap_or_default();
        let nonce: Nonce = nonce.map(|n| n.as_ref().clone()).unwrap_or_default();
        let plaintext = plaintext.into();
        let (ciphertext, auth) = aead_chacha20_poly1305_encrypt_with_aad(
            plaintext,
            self.into(),
            (&nonce).into(),
            &aad
        );
        EncryptedMessage::new(ciphertext, aad, nonce, auth.into())
    }

    /// Encrypt the given plaintext with this key, and the given digest of the plaintext, and nonce.
    pub fn encrypt_with_digest(
        &self,
        plaintext: impl Into<Vec<u8>>,
        digest: impl AsRef<Digest>,
        nonce: Option<impl AsRef<Nonce>>
    ) -> EncryptedMessage {
        let cbor: CBOR = digest.as_ref().clone().into();
        let data = cbor.to_cbor_data();
        self.encrypt(plaintext, Some(data), nonce)
    }

    /// Decrypt the given encrypted message with this key.
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        aead_chacha20_poly1305_decrypt_with_aad(
            message.ciphertext(),
            self.into(),
            message.nonce().into(),
            message.aad(),
            message.authentication_tag().into()
        )
    }
}

/// Implements Default to create a new random symmetric key.
impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements `AsRef<SymmetricKey>` to allow self-reference.
impl AsRef<SymmetricKey> for SymmetricKey {
    fn as_ref(&self) -> &SymmetricKey {
        self
    }
}

/// Implements conversion from a SymmetricKey reference to a byte array reference.
impl<'a> From<&'a SymmetricKey> for &'a [u8; SymmetricKey::SYMMETRIC_KEY_SIZE] {
    fn from(key: &'a SymmetricKey) -> Self {
        &key.0
    }
}

/// Implements conversion from a SymmetricKey reference to a SymmetricKey.
impl From<&SymmetricKey> for SymmetricKey {
    fn from(key: &SymmetricKey) -> Self {
        key.clone()
    }
}

/// Implements conversion from a SymmetricKey to a `Vec<u8>`.
impl From<SymmetricKey> for Vec<u8> {
    fn from(key: SymmetricKey) -> Self {
        key.0.to_vec()
    }
}

/// Implements conversion from a SymmetricKey reference to a `Vec<u8>`.
impl From<&SymmetricKey> for Vec<u8> {
    fn from(key: &SymmetricKey) -> Self {
        key.0.to_vec()
    }
}

/// Implements conversion from a `Vec<u8>` to a SymmetricKey.
impl TryFrom<Vec<u8>> for SymmetricKey {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_data_ref(value)
    }
}

/// Implements Debug formatting to display the key in hexadecimal format.
impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey({})", self.hex())
    }
}

/// Implements CBORTagged to provide the CBOR tag for the SymmetricKey.
impl CBORTagged for SymmetricKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SYMMETRIC_KEY])
    }
}

/// Implements conversion from SymmetricKey to CBOR for serialization.
impl From<SymmetricKey> for CBOR {
    fn from(value: SymmetricKey) -> Self {
        value.tagged_cbor()
    }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
impl CBORTaggedEncodable for SymmetricKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.0)
    }
}

/// Implements `TryFrom<CBOR>` for SymmetricKey to support conversion from CBOR data.
impl TryFrom<CBOR> for SymmetricKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_untagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for SymmetricKey {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let bytes = CBOR::try_into_byte_string(cbor)?;
        let instance = Self::from_data_ref(bytes)?;
        Ok(instance)
    }
}
