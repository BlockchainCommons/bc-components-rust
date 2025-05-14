//! This module provides functionality to securely lock (encrypt) and unlock (decrypt) a symmetric
//! content key using secret-based key derivation. Multiple derivation methods are supported,
//! ensuring extensibility and security.

use crate::{ tags, EncryptedMessage };
use anyhow::{ Result, Error };
use dcbor::prelude::*;

use super::{ Argon2id, DerivationParams, KeyDerivation, Scrypt, SymmetricKey, HKDF, PBKDF2 };

/// # Overview
/// Provides symmetric encryption and decryption of content keys using various
/// key derivation methods (HKDF, PBKDF2, Scrypt, Argon2id). This module
/// implements types and traits to wrap the encryption mechanisms, and encodes
/// methods and parameters in CBOR according to the defined CDDL schemas.
///
/// # Usage
/// - Call `EncryptedKey::lock` with a chosen key derivation method, secret, and
///   content key to produce an encrypted key.
/// - Retrieve the original content key by calling `EncryptedKey::unlock` with
///   the correct secret.
///
/// # Encoding
/// The form of an `EncryptedKey` is an `EncryptedMessage` that contains the
/// encrypted content key, with its Additional Authenticated Data (AAD) being
/// the CBOR encoding of the key derivation method and parameters used for key
/// derivation. The same key derivation method and parameters must be used to
/// unlock the content key.
///
/// CDDL:
/// ```cddl
/// EncryptedKey = #6.40027(EncryptedMessage) ; TAG_ENCRYPTED_KEY
///
/// EncryptedMessage =
///     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, aad: bstr .cbor KeyDerivation ]) ; TAG_ENCRYPTED
///
/// KeyDerivation = HKDFParams / PBKDF2Params / ScryptParams / Argon2idParams
///
/// HKDFParams = [HKDF, Salt, HashType]
/// PBKDF2Params = [PBKDF2, Salt, iterations: uint, HashType]
/// ScryptParams = [Scrypt, Salt, log_n: uint, r: uint, p: uint]
/// Argon2idParams = [Argon2id, Salt]
///
/// KeyDerivationMethod = HKDF / PBKDF2 / Scrypt / Argon2id
///
/// HKDF = 0
/// PBKDF2 = 1
/// Scrypt = 2
/// Argon2id = 3
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
        secret: impl AsRef<[u8]>,
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
            KeyDerivationMethod::Argon2id => {
                let params = Argon2id::new();
                let encrypted_key = params.lock(content_key, secret);
                Self { params: DerivationParams::Argon2id(params), encrypted_key }
            }
        }
    }

    pub fn unlock(&self, secret: impl AsRef<[u8]>) -> Result<SymmetricKey> {
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
            KeyDerivationMethod::Argon2id => {
                let params = Argon2id::try_from(cbor)?;
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
        let params_cbor = CBOR::try_from_data(encrypted_key.aad())?;
        let params = params_cbor.try_into()?;
        Ok(Self { params, encrypted_key })
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
    Argon2id = 3,
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
            3 => Some(KeyDerivationMethod::Argon2id),
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
            KeyDerivationMethod::Argon2id => write!(f, "Argon2id"),
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
