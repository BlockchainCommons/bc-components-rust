use dcbor::prelude::*;

use super::{
    Argon2idParams, HKDFParams, KeyDerivationMethod, PBKDF2Params,
    SSHAgentParams, ScryptParams,
};

/// Enum representing the derivation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDerivationParams {
    HKDF(HKDFParams),
    PBKDF2(PBKDF2Params),
    Scrypt(ScryptParams),
    Argon2id(Argon2idParams),
    SSHAgent(SSHAgentParams),
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
