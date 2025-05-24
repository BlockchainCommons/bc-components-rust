use anyhow::Result;
use dcbor::prelude::*;

use super::{KeyDerivation, KeyDerivationMethod, SALT_LEN};
use crate::{EncryptedMessage, Salt, SymmetricKey};

/// Struct representing SSH Agent parameters.
///
/// CDDL:
/// ```cddl
/// SSHAgentParams = [4, Salt, id: tstr]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHAgentParams {
    salt: Salt,
    id: String,
}

impl SSHAgentParams {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), String::new())
    }

    pub fn new_opt(salt: Salt, id: String) -> Self { Self { salt, id } }

    pub fn salt(&self) -> &Salt { &self.salt }

    pub fn id(&self) -> &String { &self.id }
}

impl KeyDerivation for SSHAgentParams {
    const INDEX: usize = KeyDerivationMethod::SSHAgent as usize;

    fn lock(
        &self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        todo!()
    }

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey> {
        todo!()
    }
}

impl std::fmt::Display for SSHAgentParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHAgent({})", self.id)
    }
}

impl Into<CBOR> for SSHAgentParams {
    fn into(self) -> CBOR {
        vec![CBOR::from(Self::INDEX), self.salt.into(), self.id.into()].into()
    }
}

impl TryFrom<CBOR> for SSHAgentParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.try_into_array()?;
        a.len()
            .eq(&3)
            .then_some(())
            .ok_or_else(|| dcbor::Error::msg("Invalid SSHAgentParams"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing salt"))?
            .try_into()?;
        let id: String = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing id"))?
            .try_into()?;
        Ok(SSHAgentParams { salt, id })
    }
}
