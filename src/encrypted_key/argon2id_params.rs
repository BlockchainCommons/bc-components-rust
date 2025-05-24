use anyhow::Result;
use bc_crypto::argon2id;
use dcbor::prelude::*;

use super::{KeyDerivation, KeyDerivationMethod, SALT_LEN};
use crate::{EncryptedMessage, Nonce, Salt, SymmetricKey};

/// Struct representing Argon2id parameters.
///
/// CDDL:
/// ```cddl
/// Argon2idParams = [3, Salt]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2idParams {
    salt: Salt,
}

impl Argon2idParams {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap())
    }

    pub fn new_opt(salt: Salt) -> Self { Self { salt } }

    pub fn salt(&self) -> &Salt { &self.salt }
}

impl KeyDerivation for Argon2idParams {
    const INDEX: usize = KeyDerivationMethod::Argon2id as usize;

    fn lock(
        &self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        let derived_key: SymmetricKey =
            argon2id(secret, &self.salt, 32).try_into().unwrap();
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
        let derived_key: SymmetricKey =
            argon2id(secret, &self.salt, 32).try_into()?;
        derived_key.decrypt(encrypted_key)?.try_into()
    }
}

impl std::fmt::Display for Argon2idParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Argon2id")
    }
}

impl Into<CBOR> for Argon2idParams {
    fn into(self) -> CBOR {
        vec![CBOR::from(Self::INDEX), self.salt.into()].into()
    }
}

impl TryFrom<CBOR> for Argon2idParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.try_into_array()?;
        a.len()
            .eq(&2)
            .then_some(())
            .ok_or_else(|| dcbor::Error::msg("Invalid Argon2idParams"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing salt"))?
            .try_into()?;
        Ok(Argon2idParams { salt })
    }
}
