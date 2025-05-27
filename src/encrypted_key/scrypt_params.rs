use anyhow::Result;
use bc_crypto::scrypt_opt;
use dcbor::prelude::*;

use super::{KeyDerivation, KeyDerivationMethod, SALT_LEN};
use crate::{EncryptedMessage, Nonce, Salt, SymmetricKey};

/// Struct representing Scrypt parameters.
///
/// CDDL:
/// ```cddl
/// ScryptParams = [2, Salt, log_n: uint, r: uint, p: uint]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScryptParams {
    salt: Salt,
    log_n: u8,
    r: u32,
    p: u32,
}

impl ScryptParams {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), 15, 8, 1)
    }

    pub fn new_opt(salt: Salt, log_n: u8, r: u32, p: u32) -> Self {
        Self { salt, log_n, r, p }
    }

    pub fn salt(&self) -> &Salt { &self.salt }

    pub fn log_n(&self) -> u8 { self.log_n }

    pub fn r(&self) -> u32 { self.r }

    pub fn p(&self) -> u32 { self.p }
}

impl KeyDerivation for ScryptParams {
    const INDEX: usize = KeyDerivationMethod::Scrypt as usize;
    fn lock(
        &mut self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        let derived_key: SymmetricKey =
            scrypt_opt(secret, &self.salt, 32, self.log_n, self.r, self.p)
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
        let derived_key: SymmetricKey =
            scrypt_opt(secret, &self.salt, 32, self.log_n, self.r, self.p)
                .try_into()?;
        derived_key.decrypt(encrypted_message)?.try_into()
    }
}

impl std::fmt::Display for ScryptParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scrypt")
    }
}

impl Into<CBOR> for ScryptParams {
    fn into(self) -> CBOR {
        vec![
            CBOR::from(Self::INDEX),
            self.salt.into(),
            self.log_n.into(),
            self.r.into(),
            self.p.into(),
        ]
        .into()
    }
}

impl TryFrom<CBOR> for ScryptParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.try_into_array()?;
        a.len()
            .eq(&5)
            .then_some(())
            .ok_or_else(|| dcbor::Error::msg("Invalid ScryptParams"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing salt"))?
            .try_into()?;
        let log_n: u8 = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing log_n"))?
            .try_into()?;
        let r: u32 = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing r"))?
            .try_into()?;
        let p: u32 = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing p"))?
            .try_into()?;
        Ok(Self { salt, log_n, r, p })
    }
}
