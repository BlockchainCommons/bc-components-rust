use anyhow::{Error, Result};
use dcbor::prelude::*;

/// Enum representing the supported hash types.
///
/// CDDL:
/// ```cddl
/// HashType = SHA256 / SHA512
/// SHA256 = 0
/// SHA512 = 1
/// ```
#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashType {
    SHA256 = 0,
    SHA512 = 1,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashType::SHA256 => write!(f, "SHA256"),
            HashType::SHA512 => write!(f, "SHA512"),
        }
    }
}

impl From<HashType> for CBOR {
    fn from(val: HashType) -> Self { CBOR::from(val as u8) }
}

impl TryFrom<CBOR> for HashType {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let i: u8 = cbor.try_into()?;
        match i {
            0 => Ok(HashType::SHA256),
            1 => Ok(HashType::SHA512),
            _ => Err(Error::msg("Invalid HashType")),
        }
    }
}
