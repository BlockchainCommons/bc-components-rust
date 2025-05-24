use anyhow::Result;
use bc_crypto::{hash::pbkdf2_hmac_sha512, pbkdf2_hmac_sha256};
use dcbor::prelude::*;

use super::{HashType, KeyDerivation, KeyDerivationMethod, SALT_LEN};
use crate::{EncryptedMessage, Nonce, Salt, SymmetricKey};

/// Struct representing PBKDF2 parameters.
///
/// CDDL:
/// ```cddl
/// PBKDF2Params = [1, Salt, iterations: uint, HashType]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PBKDF2Params {
    salt: Salt,
    iterations: u32,
    hash_type: HashType,
}

impl PBKDF2Params {
    pub fn new() -> Self {
        Self::new_opt(
            Salt::new_with_len(SALT_LEN).unwrap(),
            100_000,
            HashType::SHA256,
        )
    }

    pub fn new_opt(salt: Salt, iterations: u32, hash_type: HashType) -> Self {
        Self { salt, iterations, hash_type }
    }

    pub fn salt(&self) -> &Salt { &self.salt }

    pub fn iterations(&self) -> u32 { self.iterations }

    pub fn hash_type(&self) -> HashType { self.hash_type }
}

impl KeyDerivation for PBKDF2Params {
    const INDEX: usize = KeyDerivationMethod::PBKDF2 as usize;

    fn lock(
        &self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        let derived_key: SymmetricKey = (match self.hash_type {
            HashType::SHA256 => {
                pbkdf2_hmac_sha256(secret, &self.salt, self.iterations, 32)
            }
            HashType::SHA512 => {
                pbkdf2_hmac_sha512(secret, &self.salt, self.iterations, 32)
            }
        })
        .try_into()
        .unwrap();
        let encoded_method: Vec<u8> = self.to_cbor_data();
        Ok(derived_key.encrypt(
            content_key,
            Some(encoded_method),
            Option::<Nonce>::None,
        ))
    }

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey> {
        let derived_key: SymmetricKey = (match self.hash_type {
            HashType::SHA256 => {
                pbkdf2_hmac_sha256(secret, &self.salt, self.iterations, 32)
            }
            HashType::SHA512 => {
                pbkdf2_hmac_sha512(secret, &self.salt, self.iterations, 32)
            }
        })
        .try_into()?;
        derived_key.decrypt(encrypted_key)?.try_into()
    }
}

impl std::fmt::Display for PBKDF2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PBKDF2({})", self.hash_type)
    }
}

impl Into<CBOR> for PBKDF2Params {
    fn into(self) -> CBOR {
        vec![
            CBOR::from(Self::INDEX),
            self.salt.into(),
            self.iterations.into(),
            self.hash_type.into(),
        ]
        .into()
    }
}

impl TryFrom<CBOR> for PBKDF2Params {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.try_into_array()?;
        a.len()
            .eq(&4)
            .then_some(())
            .ok_or_else(|| dcbor::Error::msg("Invalid PBKDF2Params"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing salt"))?
            .try_into()?;
        let iterations: u32 = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing iterations"))?
            .try_into()?;
        let hash_type: HashType = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing hash type"))?
            .try_into()?;
        Ok(Self { salt, iterations, hash_type })
    }
}
