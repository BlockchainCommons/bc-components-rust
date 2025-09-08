use dcbor::prelude::*;

use super::{
    Argon2idParams, HKDFParams, KeyDerivation, KeyDerivationMethod,
    PBKDF2Params, SSHAgentParams, ScryptParams,
};
use crate::{EncryptedMessage, Result, SymmetricKey};

/// Enum representing the derivation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDerivationParams {
    HKDF(HKDFParams),
    PBKDF2(PBKDF2Params),
    Scrypt(ScryptParams),
    Argon2id(Argon2idParams),
    SSHAgent(SSHAgentParams),
}

impl KeyDerivationParams {
    /// Returns the key derivation method associated with the parameters.
    pub fn method(&self) -> KeyDerivationMethod {
        match self {
            KeyDerivationParams::HKDF(_) => KeyDerivationMethod::HKDF,
            KeyDerivationParams::PBKDF2(_) => KeyDerivationMethod::PBKDF2,
            KeyDerivationParams::Scrypt(_) => KeyDerivationMethod::Scrypt,
            KeyDerivationParams::Argon2id(_) => KeyDerivationMethod::Argon2id,
            KeyDerivationParams::SSHAgent(_) => KeyDerivationMethod::SSHAgent,
        }
    }

    pub fn is_password_based(&self) -> bool {
        matches!(
            self,
            KeyDerivationParams::PBKDF2(_)
                | KeyDerivationParams::Scrypt(_)
                | KeyDerivationParams::Argon2id(_)
        )
    }

    pub fn is_ssh_agent(&self) -> bool {
        matches!(self, KeyDerivationParams::SSHAgent(_))
    }

    pub fn lock(
        &mut self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        match self {
            KeyDerivationParams::HKDF(params) => {
                params.lock(content_key, secret)
            }
            KeyDerivationParams::PBKDF2(params) => {
                params.lock(content_key, secret)
            }
            KeyDerivationParams::Scrypt(params) => {
                params.lock(content_key, secret)
            }
            KeyDerivationParams::Argon2id(params) => {
                params.lock(content_key, secret)
            }
            KeyDerivationParams::SSHAgent(params) => {
                params.lock(content_key, secret)
            }
        }
    }
}

impl std::fmt::Display for KeyDerivationParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDerivationParams::HKDF(params) => write!(f, "{}", params),
            KeyDerivationParams::PBKDF2(params) => write!(f, "{}", params),
            KeyDerivationParams::Scrypt(params) => write!(f, "{}", params),
            KeyDerivationParams::Argon2id(params) => write!(f, "{}", params),
            KeyDerivationParams::SSHAgent(params) => write!(f, "{}", params),
        }
    }
}

impl From<KeyDerivationParams> for CBOR {
    fn from(value: KeyDerivationParams) -> Self {
        match value {
            KeyDerivationParams::HKDF(params) => params.into(),
            KeyDerivationParams::PBKDF2(params) => params.into(),
            KeyDerivationParams::Scrypt(params) => params.into(),
            KeyDerivationParams::Argon2id(params) => params.into(),
            KeyDerivationParams::SSHAgent(params) => params.into(),
        }
    }
}

impl TryFrom<CBOR> for KeyDerivationParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.clone().try_into_array()?;
        let mut iter = a.into_iter();
        let index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        match KeyDerivationMethod::from_index(index) {
            Some(KeyDerivationMethod::HKDF) => {
                Ok(KeyDerivationParams::HKDF(HKDFParams::try_from(cbor)?))
            }
            Some(KeyDerivationMethod::PBKDF2) => {
                Ok(KeyDerivationParams::PBKDF2(PBKDF2Params::try_from(cbor)?))
            }
            Some(KeyDerivationMethod::Scrypt) => {
                Ok(KeyDerivationParams::Scrypt(ScryptParams::try_from(cbor)?))
            }
            Some(KeyDerivationMethod::Argon2id) => Ok(
                KeyDerivationParams::Argon2id(Argon2idParams::try_from(cbor)?),
            ),
            Some(KeyDerivationMethod::SSHAgent) => Ok(
                KeyDerivationParams::SSHAgent(SSHAgentParams::try_from(cbor)?),
            ),
            None => Err(dcbor::Error::msg("Invalid KeyDerivationMethod")),
        }
    }
}
