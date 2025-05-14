use super::{Argon2id, KeyDerivationMethod, Scrypt, HKDF, PBKDF2};
use dcbor::prelude::*;

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
    Argon2id(Argon2id),
}

impl std::fmt::Display for DerivationParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerivationParams::HKDF(params) => write!(f, "{}", params),
            DerivationParams::PBKDF2(params) => write!(f, "{}", params),
            DerivationParams::Scrypt(params) => write!(f, "{}", params),
            DerivationParams::Argon2id(params) => write!(f, "{}", params),
        }
    }
}

impl From<DerivationParams> for CBOR {
    fn from(value: DerivationParams) -> Self {
        match value {
            DerivationParams::HKDF(params) => params.into(),
            DerivationParams::PBKDF2(params) => params.into(),
            DerivationParams::Scrypt(params) => params.into(),
            DerivationParams::Argon2id(params) => params.into(),
        }
    }
}

impl TryFrom<CBOR> for DerivationParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.clone().try_into_array()?;
        let mut iter = a.into_iter();
        let index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        match KeyDerivationMethod::from_index(index) {
            Some(KeyDerivationMethod::HKDF) => Ok(DerivationParams::HKDF(HKDF::try_from(cbor)?)),
            Some(KeyDerivationMethod::PBKDF2) =>
                Ok(DerivationParams::PBKDF2(PBKDF2::try_from(cbor)?)),
            Some(KeyDerivationMethod::Scrypt) =>
                Ok(DerivationParams::Scrypt(Scrypt::try_from(cbor)?)),
            Some(KeyDerivationMethod::Argon2id) =>
                Ok(DerivationParams::Argon2id(Argon2id::try_from(cbor)?)),
            None => Err(dcbor::Error::msg("Invalid KeyDerivationMethod")),
        }
    }
}
