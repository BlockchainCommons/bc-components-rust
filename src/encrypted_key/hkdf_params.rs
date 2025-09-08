use crate::{Result};
use bc_crypto::{hash::hkdf_hmac_sha512, hkdf_hmac_sha256};
use dcbor::prelude::*;

use super::{HashType, KeyDerivation, SALT_LEN};
use crate::{EncryptedMessage, KeyDerivationMethod, Nonce, Salt, SymmetricKey};

/// Struct representing HKDF parameters.
///
/// CDDL:
/// ```cddl
/// HKDFParams = [0, Salt, HashType]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HKDFParams {
    salt: Salt,
    hash_type: HashType,
}

impl HKDFParams {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), HashType::SHA256)
    }

    pub fn new_opt(salt: Salt, hash_type: HashType) -> Self {
        Self { salt, hash_type }
    }

    pub fn salt(&self) -> &Salt { &self.salt }

    pub fn hash_type(&self) -> HashType { self.hash_type }
}

impl Default for HKDFParams {
    fn default() -> Self { Self::new() }
}

impl KeyDerivation for HKDFParams {
    const INDEX: usize = KeyDerivationMethod::HKDF as usize;

    fn lock(
        &mut self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        let derived_key: SymmetricKey = (match self.hash_type {
            HashType::SHA256 => hkdf_hmac_sha256(secret, &self.salt, 32),
            HashType::SHA512 => hkdf_hmac_sha512(secret, &self.salt, 32),
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
        encrypted_message: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey> {
        let derived_key: SymmetricKey = (match self.hash_type {
            HashType::SHA256 => hkdf_hmac_sha256(secret, &self.salt, 32),
            HashType::SHA512 => hkdf_hmac_sha512(secret, &self.salt, 32),
        })
        .try_into()?;
        let content_key = derived_key.decrypt(encrypted_message)?.try_into()?;
        Ok(content_key)
    }
}

impl std::fmt::Display for HKDFParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HKDF({})", self.hash_type)
    }
}

impl From<HKDFParams> for CBOR {
    fn from(val: HKDFParams) -> Self {
        vec![
            CBOR::from(HKDFParams::INDEX),
            val.salt.into(),
            val.hash_type.into(),
        ]
        .into()
    }
}

impl TryFrom<CBOR> for HKDFParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.try_into_array()?;
        a.len()
            .eq(&3)
            .then_some(())
            .ok_or_else(|| dcbor::Error::msg("Invalid HKDFParams"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing salt"))?
            .try_into()?;
        let hash_type: HashType = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing hash type"))?
            .try_into()?;
        Ok(Self { salt, hash_type })
    }
}
