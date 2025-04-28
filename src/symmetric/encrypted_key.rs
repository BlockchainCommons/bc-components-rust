//! This module provides functionality to securely lock (encrypt) and unlock (decrypt) a symmetric
//! content key using secret-based key derivation. Multiple derivation methods are supported,
//! ensuring extensibility and security.

use crate::{ tags, EncryptedMessage, Nonce, Salt };
use bc_crypto::{ hash::hkdf_hmac_sha512, hkdf_hmac_sha256, pbkdf2_hmac_sha256, scrypt_opt };
use anyhow::{ Result, Error };
use dcbor::prelude::*;

use super::SymmetricKey;

const SALT_LEN: usize = 16;

/// # Overview
/// Provides symmetric encryption and decryption of content keys using various key derivation
/// methods (HKDF, PBKDF2, Scrypt). This module implements types and traits to wrap the encryption
/// mechanisms, and encodes methods and parameters in CBOR according to the defined CDDL schemas.
///
/// # Usage
/// - Call `EncryptedKey::lock` with a chosen key derivation method, secret, and content key to produce an encrypted key.
/// - Retrieve the original content key by calling `EncryptedKey::unlock` with the correct secret.
///
/// # Encoding
/// The form of an `EncryptedKey` is an `EncryptedMessage` that contains the encrypted content key,
/// with its Additional Authenticated Data (AAD) being the CBOR encoding of the key derivation method and
/// parameters used for key derivation. The same key derivation method and parameters must be used
/// to unlock the content key.
///
/// CDDL:
/// ```cddl
/// EncryptedKey = #6.40027(EncryptedMessage) ; TAG_ENCRYPTED_KEY
///
/// EncryptedMessage =
///     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, aad: bstr .cbor KeyDerivation ]) ; TAG_ENCRYPTED
///
/// KeyDerivation = HKDFParams / PBKDF2Params / ScryptParams
///
/// HKDFParams = [HKDF, Salt, HashType]
/// PBKDF2Params = [PBKDF2, Salt, iterations: uint, HashType]
/// ScryptParams = [Scrypt, Salt, log_n: uint, r: uint, p: uint]
///
/// KeyDerivationMethod = HKDF / PBKDF2 / Scrypt
///
/// HKDF = 0
/// PBKDF2 = 1
/// Scrypt = 2
///
/// HashType = SHA256 / SHA512
///
/// SHA256 = 0
/// SHA512 = 1
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKey {
    params: DerivationParams,
    encrypted_key: EncryptedMessage,
}

impl EncryptedKey {
    pub fn lock(
        method: KeyDerivationMethod,
        secret: impl Into<Vec<u8>>,
        content_key: &SymmetricKey
    ) -> Self {
        match method {
            KeyDerivationMethod::HKDF => {
                let params = HKDF::new();
                let encrypted_key = params.lock(content_key, secret);
                Self { params: DerivationParams::HKDF(params), encrypted_key }
            }
            KeyDerivationMethod::PBKDF2 => {
                let params = PBKDF2::new();
                let encrypted_key = params.lock(content_key, secret);
                Self { params: DerivationParams::PBKDF2(params), encrypted_key }
            }
            KeyDerivationMethod::Scrypt => {
                let params = Scrypt::new();
                let encrypted_key = params.lock(content_key, secret);
                Self { params: DerivationParams::Scrypt(params), encrypted_key }
            }
        }
    }

    pub fn unlock(&self, secret: impl Into<Vec<u8>>) -> Result<SymmetricKey> {
        let encrypted_message = &self.encrypted_key;
        let aad = encrypted_message.aad();
        let cbor = CBOR::try_from_data(aad)?;
        let array = cbor.clone().try_into_array()?;
        let method: KeyDerivationMethod = array
            .get(0)
            .ok_or_else(|| Error::msg("Missing method"))?
            .try_into()?;
        match method {
            KeyDerivationMethod::HKDF => {
                let params = HKDF::try_from(cbor)?;
                params.unlock(&encrypted_message, secret)
            }
            KeyDerivationMethod::PBKDF2 => {
                let params = PBKDF2::try_from(cbor)?;
                params.unlock(&encrypted_message, secret)
            }
            KeyDerivationMethod::Scrypt => {
                let params = Scrypt::try_from(cbor)?;
                params.unlock(&encrypted_message, secret)
            }
        }
    }
}

impl std::fmt::Display for EncryptedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptedKey({})", self.params)
    }
}

impl CBORTagged for EncryptedKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_ENCRYPTED_KEY])
    }
}

impl From<EncryptedKey> for CBOR {
    fn from(value: EncryptedKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for EncryptedKey {
    fn untagged_cbor(&self) -> CBOR {
        return self.encrypted_key.clone().into();
    }
}

impl TryFrom<CBOR> for EncryptedKey {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(value)
    }
}

impl CBORTaggedDecodable for EncryptedKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let encrypted_key: EncryptedMessage = untagged_cbor.try_into()?;
        let params_cbor = CBOR::try_from_data(encrypted_key.aad().clone())?;
        let params = params_cbor.try_into()?;
        Ok(Self { params, encrypted_key })
    }
}

/// Enum representing the supported hash types.
///
/// CDDL:
/// ```cddl
/// HashType = SHA256 / SHA512
/// SHA256 = 0
/// SHA512 = 1
/// ```
#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashType {
    SHA256 = 0,
    SHA512 = 1,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashType::SHA256 => write!(f, "SHA256"),
            HashType::SHA512 => write!(f, "SHA512"),
        }
    }
}

impl Into<CBOR> for HashType {
    fn into(self) -> CBOR {
        CBOR::from(self as u8)
    }
}

impl TryFrom<CBOR> for HashType {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let i: u8 = cbor.try_into()?;
        match i {
            0 => Ok(HashType::SHA256),
            1 => Ok(HashType::SHA512),
            _ => Err(Error::msg("Invalid HashType")),
        }
    }
}

/// Enum representing the supported key derivation methods.
///
/// CDDL:
/// ```cddl
/// KeyDerivationMethod = 0..2
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyDerivationMethod {
    HKDF = 0,
    PBKDF2 = 1,
    Scrypt = 2,
}

impl KeyDerivationMethod {
    /// Returns the zero-based index of the key derivation method.
    pub fn index(&self) -> usize {
        *self as usize
    }

    /// Attempts to create a `KeyDerivationMethod` from a zero-based index.
    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(KeyDerivationMethod::HKDF),
            1 => Some(KeyDerivationMethod::PBKDF2),
            2 => Some(KeyDerivationMethod::Scrypt),
            _ => None,
        }
    }
}

impl std::fmt::Display for KeyDerivationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDerivationMethod::HKDF => write!(f, "HKDF"),
            KeyDerivationMethod::PBKDF2 => write!(f, "PBKDF2"),
            KeyDerivationMethod::Scrypt => write!(f, "Scrypt"),
        }
    }
}

impl TryFrom<&CBOR> for KeyDerivationMethod {
    type Error = Error;

    fn try_from(cbor: &CBOR) -> Result<Self> {
        let i: usize = cbor.clone().try_into()?;
        KeyDerivationMethod::from_index(i).ok_or_else(|| Error::msg("Invalid KeyDerivationMethod"))
    }
}

/// Trait for key derivation implementations.
pub trait KeyDerivation: Into<CBOR> + TryFrom<CBOR> + Clone {
    const INDEX: usize;

    fn lock(&self, content_key: &SymmetricKey, secret: impl Into<Vec<u8>>) -> EncryptedMessage;
    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl Into<Vec<u8>>
    ) -> Result<SymmetricKey>;
}

/// Struct representing HKDF parameters.
///
/// CDDL:
/// ```cddl
/// HKDF = [0, Salt, HashType]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HKDF {
    salt: Salt,
    hash_type: HashType,
}

impl KeyDerivation for HKDF {
    const INDEX: usize = KeyDerivationMethod::HKDF as usize;

    fn lock(&self, content_key: &SymmetricKey, secret: impl Into<Vec<u8>>) -> EncryptedMessage {
        let derived_key: SymmetricKey = (
            match self.hash_type {
                HashType::SHA256 => hkdf_hmac_sha256(secret.into(), &self.salt, 32),
                HashType::SHA512 => hkdf_hmac_sha512(secret.into(), &self.salt, 32),
            }
        )
            .try_into()
            .unwrap();
        let encoded_method: Vec<u8> = self.to_cbor_data();
        derived_key.encrypt(content_key, Some(encoded_method), Option::<Nonce>::None)
    }

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl Into<Vec<u8>>
    ) -> Result<SymmetricKey> {
        let derived_key: SymmetricKey = (
            match self.hash_type {
                HashType::SHA256 => hkdf_hmac_sha256(secret.into(), &self.salt, 32),
                HashType::SHA512 => hkdf_hmac_sha512(secret.into(), &self.salt, 32),
            }
        ).try_into()?;
        let content_key = derived_key.decrypt(encrypted_key)?.try_into()?;
        Ok(content_key)
    }
}

impl std::fmt::Display for HKDF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HKDF({})", self.hash_type)
    }
}

impl Into<CBOR> for HKDF {
    fn into(self) -> CBOR {
        vec![CBOR::from(Self::INDEX), self.salt.into(), self.hash_type.into()].into()
    }
}

impl TryFrom<CBOR> for HKDF {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let a = cbor.try_into_array()?;
        a
            .len()
            .eq(&3)
            .then_some(())
            .ok_or_else(|| Error::msg("Invalid HKDF CBOR"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| Error::msg("Missing salt"))?
            .try_into()?;
        let hash_type: HashType = iter
            .next()
            .ok_or_else(|| Error::msg("Missing hash type"))?
            .try_into()?;
        Ok(Self { salt, hash_type })
    }
}

impl HKDF {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), HashType::SHA256)
    }

    pub fn new_opt(salt: Salt, hash_type: HashType) -> Self {
        Self { salt, hash_type }
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }
}

/// Struct representing PBKDF2 parameters.
///
/// CDDL:
/// ```cddl
/// PBKDF2 = [1, Salt, iterations: uint, HashType]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PBKDF2 {
    salt: Salt,
    iterations: u32,
    hash_type: HashType,
}

impl KeyDerivation for PBKDF2 {
    const INDEX: usize = KeyDerivationMethod::PBKDF2 as usize;

    fn lock(&self, content_key: &SymmetricKey, secret: impl Into<Vec<u8>>) -> EncryptedMessage {
        let derived_key: SymmetricKey = (
            match self.hash_type {
                HashType::SHA256 =>
                    pbkdf2_hmac_sha256(secret.into(), &self.salt, self.iterations, 32),
                HashType::SHA512 =>
                    pbkdf2_hmac_sha256(secret.into(), &self.salt, self.iterations, 32),
            }
        )
            .try_into()
            .unwrap();
        let encoded_method: Vec<u8> = self.to_cbor_data();
        derived_key.encrypt(content_key, Some(encoded_method), Option::<Nonce>::None)
    }

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl Into<Vec<u8>>
    ) -> Result<SymmetricKey> {
        let derived_key: SymmetricKey = (
            match self.hash_type {
                HashType::SHA256 =>
                    pbkdf2_hmac_sha256(secret.into(), &self.salt, self.iterations, 32),
                HashType::SHA512 =>
                    pbkdf2_hmac_sha256(secret.into(), &self.salt, self.iterations, 32),
            }
        ).try_into()?;
        derived_key.decrypt(encrypted_key)?.try_into()
    }
}

impl std::fmt::Display for PBKDF2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PBKDF2({})", self.hash_type)
    }
}

impl Into<CBOR> for PBKDF2 {
    fn into(self) -> CBOR {
        vec![
            CBOR::from(Self::INDEX),
            self.salt.into(),
            self.iterations.into(),
            self.hash_type.into()
        ].into()
    }
}

impl TryFrom<CBOR> for PBKDF2 {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let a = cbor.try_into_array()?;
        a
            .len()
            .eq(&4)
            .then_some(())
            .ok_or_else(|| Error::msg("Invalid PBKDF2 CBOR"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| Error::msg("Missing salt"))?
            .try_into()?;
        let iterations: u32 = iter
            .next()
            .ok_or_else(|| Error::msg("Missing iterations"))?
            .try_into()?;
        let hash_type: HashType = iter
            .next()
            .ok_or_else(|| Error::msg("Missing hash type"))?
            .try_into()?;
        Ok(Self { salt, iterations, hash_type })
    }
}

impl PBKDF2 {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), 100_000, HashType::SHA256)
    }

    pub fn new_opt(salt: Salt, iterations: u32, hash_type: HashType) -> Self {
        Self { salt, iterations, hash_type }
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }
}

/// Struct representing Scrypt parameters.
///
/// CDDL:
/// ```cddl
/// Scrypt = [2, Salt, log_n: uint, r: uint, p: uint]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scrypt {
    salt: Salt,
    log_n: u8,
    r: u32,
    p: u32,
}

impl KeyDerivation for Scrypt {
    const INDEX: usize = KeyDerivationMethod::Scrypt as usize;
    fn lock(&self, content_key: &SymmetricKey, secret: impl Into<Vec<u8>>) -> EncryptedMessage {
        let derived_key: SymmetricKey = scrypt_opt(
            secret.into(),
            &self.salt,
            32,
            self.log_n,
            self.r,
            self.p
        )
            .try_into()
            .unwrap();
        let encoded_method: Vec<u8> = self.to_cbor_data();
        derived_key.encrypt(content_key, Some(encoded_method), Option::<Nonce>::None)
    }

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl Into<Vec<u8>>
    ) -> Result<SymmetricKey> {
        let derived_key: SymmetricKey = scrypt_opt(
            secret.into(),
            &self.salt,
            32,
            self.log_n,
            self.r,
            self.p
        ).try_into()?;
        derived_key.decrypt(encrypted_key)?.try_into()
    }
}

impl std::fmt::Display for Scrypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scrypt")
    }
}

impl Into<CBOR> for Scrypt {
    fn into(self) -> CBOR {
        vec![
            CBOR::from(Self::INDEX),
            self.salt.into(),
            self.log_n.into(),
            self.r.into(),
            self.p.into()
        ].into()
    }
}

impl TryFrom<CBOR> for Scrypt {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let a = cbor.try_into_array()?;
        a
            .len()
            .eq(&5)
            .then_some(())
            .ok_or_else(|| Error::msg("Invalid Scrypt CBOR"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| Error::msg("Missing salt"))?
            .try_into()?;
        let log_n: u8 = iter
            .next()
            .ok_or_else(|| Error::msg("Missing log_n"))?
            .try_into()?;
        let r: u32 = iter
            .next()
            .ok_or_else(|| Error::msg("Missing r"))?
            .try_into()?;
        let p: u32 = iter
            .next()
            .ok_or_else(|| Error::msg("Missing p"))?
            .try_into()?;
        Ok(Self { salt, log_n, r, p })
    }
}

impl Scrypt {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), 15, 8, 1)
    }

    pub fn new_opt(salt: Salt, log_n: u8, r: u32, p: u32) -> Self {
        Self { salt, log_n, r, p }
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    pub fn log_n(&self) -> u8 {
        self.log_n
    }

    pub fn r(&self) -> u32 {
        self.r
    }

    pub fn p(&self) -> u32 {
        self.p
    }
}

/// Enum representing the derivation parameters.
///
/// CDDL:
/// ```cddl
/// DerivationParams = HKDF / PBKDF2 / Scrypt
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationParams {
    HKDF(HKDF),
    PBKDF2(PBKDF2),
    Scrypt(Scrypt),
}

impl std::fmt::Display for DerivationParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerivationParams::HKDF(params) => write!(f, "{}", params),
            DerivationParams::PBKDF2(params) => write!(f, "{}", params),
            DerivationParams::Scrypt(params) => write!(f, "{}", params),
        }
    }
}

impl From<DerivationParams> for CBOR {
    fn from(value: DerivationParams) -> Self {
        match value {
            DerivationParams::HKDF(params) => params.into(),
            DerivationParams::PBKDF2(params) => params.into(),
            DerivationParams::Scrypt(params) => params.into(),
        }
    }
}

impl TryFrom<CBOR> for DerivationParams {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let a = cbor.clone().try_into_array()?;
        let mut iter = a.into_iter();
        let index: usize = iter
            .next()
            .ok_or_else(|| Error::msg("Missing index"))?
            .try_into()?;
        match KeyDerivationMethod::from_index(index) {
            Some(KeyDerivationMethod::HKDF) => Ok(DerivationParams::HKDF(HKDF::try_from(cbor)?)),
            Some(KeyDerivationMethod::PBKDF2) =>
                Ok(DerivationParams::PBKDF2(PBKDF2::try_from(cbor)?)),
            Some(KeyDerivationMethod::Scrypt) =>
                Ok(DerivationParams::Scrypt(Scrypt::try_from(cbor)?)),
            None => Err(Error::msg("Invalid KeyDerivationMethod")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> &'static [u8] {
        b"correct horse battery staple"
    }

    fn test_content_key() -> SymmetricKey {
        SymmetricKey::new()
    }

    #[test]
    fn test_encrypted_key_hkdf_roundtrip() {
        crate::register_tags();
        let secret = test_secret();
        let content_key = test_content_key();

        let encrypted = EncryptedKey::lock(KeyDerivationMethod::HKDF, secret, &content_key);
        assert_eq!(format!("{}", encrypted), "EncryptedKey(HKDF(SHA256))");
        let cbor = encrypted.clone().to_cbor();
        let encrypted2 = EncryptedKey::try_from(cbor).unwrap();
        let decrypted = EncryptedKey::unlock(&encrypted2, secret).unwrap();

        assert_eq!(content_key, decrypted);
    }

    #[test]
    fn test_encrypted_key_pbkdf2_roundtrip() {
        let secret = test_secret();
        let content_key = test_content_key();

        let encrypted = EncryptedKey::lock(KeyDerivationMethod::PBKDF2, secret, &content_key);
        assert_eq!(format!("{}", encrypted), "EncryptedKey(PBKDF2(SHA256))");
        let cbor = encrypted.clone().to_cbor();
        let encrypted2 = EncryptedKey::try_from(cbor).unwrap();
        let decrypted = EncryptedKey::unlock(&encrypted2, secret).unwrap();

        assert_eq!(content_key, decrypted);
    }

    #[test]
    fn test_encrypted_key_scrypt_roundtrip() {
        let secret = test_secret();
        let content_key = test_content_key();

        let encrypted = EncryptedKey::lock(KeyDerivationMethod::Scrypt, secret, &content_key);
        assert_eq!(format!("{}", encrypted), "EncryptedKey(Scrypt)");
        let cbor = encrypted.clone().to_cbor();
        let encrypted2 = EncryptedKey::try_from(cbor).unwrap();
        let decrypted = EncryptedKey::unlock(&encrypted2, secret).unwrap();

        assert_eq!(content_key, decrypted);
    }

    #[test]
    fn test_encrypted_key_wrong_secret_fails() {
        let secret = test_secret();
        let wrong_secret = b"wrong secret";
        let content_key = test_content_key();

        let encrypted = EncryptedKey::lock(KeyDerivationMethod::HKDF, secret, &content_key);
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());

        let encrypted = EncryptedKey::lock(KeyDerivationMethod::PBKDF2, secret, &content_key);
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());

        let encrypted = EncryptedKey::lock(KeyDerivationMethod::Scrypt, secret, &content_key);
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_key_params_variant() {
        let secret = test_secret();
        let content_key = test_content_key();

        let hkdf = EncryptedKey::lock(KeyDerivationMethod::HKDF, secret, &content_key);
        matches!(hkdf.params, DerivationParams::HKDF(_));

        let pbkdf2 = EncryptedKey::lock(KeyDerivationMethod::PBKDF2, secret, &content_key);
        matches!(pbkdf2.params, DerivationParams::PBKDF2(_));

        let scrypt = EncryptedKey::lock(KeyDerivationMethod::Scrypt, secret, &content_key);
        matches!(scrypt.params, DerivationParams::Scrypt(_));
    }
}
