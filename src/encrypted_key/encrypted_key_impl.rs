//! This module provides functionality to securely lock (encrypt) and unlock
//! (decrypt) a symmetric content key using secret-based key derivation.
//! Multiple derivation methods are supported, ensuring extensibility and
//! security.

use dcbor::prelude::*;

#[cfg(feature = "ssh-agent")]
use super::SSHAgentParams;
use crate::{
    Argon2idParams, EncryptedMessage, Error, HKDFParams, KeyDerivation,
    KeyDerivationMethod, KeyDerivationParams, PBKDF2Params, Result,
    ScryptParams, SymmetricKey, tags,
};

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
/// KeyDerivation = HKDFParams / PBKDF2Params / ScryptParams / Argon2idParams / SSHAgentParams
///
/// HKDFParams = [HKDF, Salt, HashType]
/// PBKDF2Params = [PBKDF2, Salt, iterations: uint, HashType]
/// ScryptParams = [Scrypt, Salt, log_n: uint, r: uint, p: uint]
/// Argon2idParams = [Argon2id, Salt]
/// SSHAgentParams = [SSHAgent, Salt, id: tstr]
///
/// KeyDerivationMethod = HKDF / PBKDF2 / Scrypt / Argon2id / SSHAgent
///
/// HKDF = 0
/// PBKDF2 = 1
/// Scrypt = 2
/// Argon2id = 3
/// SSHAgent = 4
///
/// HashType = SHA256 / SHA512
///
/// SHA256 = 0
/// SHA512 = 1
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKey {
    params: KeyDerivationParams,
    encrypted_message: EncryptedMessage,
}

impl EncryptedKey {
    pub fn lock_opt(
        mut params: KeyDerivationParams,
        secret: impl AsRef<[u8]>,
        content_key: &SymmetricKey,
    ) -> Result<Self> {
        let encrypted_message = params.lock(content_key, secret)?;
        Ok(Self { params, encrypted_message })
    }

    pub fn lock(
        method: KeyDerivationMethod,
        secret: impl AsRef<[u8]>,
        content_key: &SymmetricKey,
    ) -> Result<Self> {
        match method {
            KeyDerivationMethod::HKDF => Self::lock_opt(
                KeyDerivationParams::HKDF(HKDFParams::new()),
                secret,
                content_key,
            ),
            KeyDerivationMethod::PBKDF2 => Self::lock_opt(
                KeyDerivationParams::PBKDF2(PBKDF2Params::new()),
                secret,
                content_key,
            ),
            KeyDerivationMethod::Scrypt => Self::lock_opt(
                KeyDerivationParams::Scrypt(ScryptParams::new()),
                secret,
                content_key,
            ),
            KeyDerivationMethod::Argon2id => Self::lock_opt(
                KeyDerivationParams::Argon2id(Argon2idParams::new()),
                secret,
                content_key,
            ),
            #[cfg(feature = "ssh-agent")]
            KeyDerivationMethod::SSHAgent => Self::lock_opt(
                KeyDerivationParams::SSHAgent(SSHAgentParams::new()),
                secret,
                content_key,
            ),
        }
    }

    pub fn encrypted_message(&self) -> &EncryptedMessage {
        &self.encrypted_message
    }

    pub fn aad_cbor(&self) -> Result<CBOR> {
        self.encrypted_message().aad_cbor().ok_or_else(|| {
            Error::general("Missing AAD CBOR in EncryptedMessage")
        })
    }

    pub fn unlock(&self, secret: impl AsRef<[u8]>) -> Result<SymmetricKey> {
        let encrypted_message = &self.encrypted_message();
        let cbor = self.aad_cbor()?;
        let array = cbor.clone().try_into_array()?;
        let method = array
            .first()
            .ok_or_else(|| Error::general("Missing method"))?
            .try_into()?;
        match method {
            KeyDerivationMethod::HKDF => {
                let params = HKDFParams::try_from(cbor)?;
                params.unlock(encrypted_message, secret)
            }
            KeyDerivationMethod::PBKDF2 => {
                let params = PBKDF2Params::try_from(cbor)?;
                params.unlock(encrypted_message, secret)
            }
            KeyDerivationMethod::Scrypt => {
                let params = ScryptParams::try_from(cbor)?;
                params.unlock(encrypted_message, secret)
            }
            KeyDerivationMethod::Argon2id => {
                let params = Argon2idParams::try_from(cbor)?;
                params.unlock(encrypted_message, secret)
            }
            #[cfg(feature = "ssh-agent")]
            KeyDerivationMethod::SSHAgent => {
                let params = SSHAgentParams::try_from(cbor)?;
                params.unlock(encrypted_message, secret)
            }
        }
    }

    pub fn is_password_based(&self) -> bool { self.params.is_password_based() }

    pub fn is_ssh_agent(&self) -> bool { self.params.is_ssh_agent() }
}

impl std::fmt::Display for EncryptedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptedKey({})", self.params)
    }
}

impl CBORTagged for EncryptedKey {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_ENCRYPTED_KEY]) }
}

impl From<EncryptedKey> for CBOR {
    fn from(value: EncryptedKey) -> Self { value.tagged_cbor() }
}

impl CBORTaggedEncodable for EncryptedKey {
    fn untagged_cbor(&self) -> CBOR { self.encrypted_message().clone().into() }
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
        Ok(Self { params, encrypted_message: encrypted_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> &'static [u8] { b"correct horse battery staple" }

    fn test_content_key() -> SymmetricKey { SymmetricKey::new() }

    #[test]
    fn test_encrypted_key_hkdf_roundtrip() {
        crate::register_tags();
        let secret = test_secret();
        let content_key = test_content_key();

        let encrypted =
            EncryptedKey::lock(KeyDerivationMethod::HKDF, secret, &content_key)
                .unwrap();
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

        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::PBKDF2,
            secret,
            &content_key,
        )
        .unwrap();
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

        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::Scrypt,
            secret,
            &content_key,
        )
        .unwrap();
        assert_eq!(format!("{}", encrypted), "EncryptedKey(Scrypt)");
        let cbor = encrypted.clone().to_cbor();
        let encrypted2 = EncryptedKey::try_from(cbor).unwrap();
        let decrypted = EncryptedKey::unlock(&encrypted2, secret).unwrap();

        assert_eq!(content_key, decrypted);
    }

    #[test]
    fn test_encrypted_key_argon2id_roundtrip() {
        let secret = test_secret();
        let content_key = test_content_key();

        let argon2id = EncryptedKey::lock(
            KeyDerivationMethod::Argon2id,
            secret,
            &content_key,
        )
        .unwrap();
        assert_eq!(format!("{}", argon2id), "EncryptedKey(Argon2id)");
        let cbor = argon2id.clone().to_cbor();
        let argon2id2 = EncryptedKey::try_from(cbor).unwrap();
        let decrypted = EncryptedKey::unlock(&argon2id2, secret).unwrap();

        assert_eq!(content_key, decrypted);
    }

    #[test]
    fn test_encrypted_key_wrong_secret_fails() {
        let secret = test_secret();
        let wrong_secret = b"wrong secret";
        let content_key = test_content_key();

        let encrypted =
            EncryptedKey::lock(KeyDerivationMethod::HKDF, secret, &content_key)
                .unwrap();
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());

        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::PBKDF2,
            secret,
            &content_key,
        )
        .unwrap();
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());

        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::Scrypt,
            secret,
            &content_key,
        )
        .unwrap();
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());

        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::Argon2id,
            secret,
            &content_key,
        )
        .unwrap();
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_key_params_variant() {
        let secret = test_secret();
        let content_key = test_content_key();

        let hkdf =
            EncryptedKey::lock(KeyDerivationMethod::HKDF, secret, &content_key)
                .unwrap();
        matches!(hkdf.params, KeyDerivationParams::HKDF(_));

        let pbkdf2 = EncryptedKey::lock(
            KeyDerivationMethod::PBKDF2,
            secret,
            &content_key,
        )
        .unwrap();
        matches!(pbkdf2.params, KeyDerivationParams::PBKDF2(_));

        let scrypt = EncryptedKey::lock(
            KeyDerivationMethod::Scrypt,
            secret,
            &content_key,
        )
        .unwrap();
        matches!(scrypt.params, KeyDerivationParams::Scrypt(_));

        let argon2id = EncryptedKey::lock(
            KeyDerivationMethod::Argon2id,
            secret,
            &content_key,
        )
        .unwrap();
        matches!(argon2id.params, KeyDerivationParams::Argon2id(_));
    }
}
