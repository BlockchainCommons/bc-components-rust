use bc_ur::prelude::*;

use crate::{Error, Result};

/// Enum representing the supported key derivation methods.
///
/// CDDL:
/// ```cddl
/// KeyDerivationMethod = HKDF / PBKDF2 / Scrypt / Argon2id
/// HKDF = 0
/// PBKDF2 = 1
/// Scrypt = 2
/// Argon2id = 3
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum KeyDerivationMethod {
    HKDF     = 0,
    PBKDF2   = 1,
    Scrypt   = 2,
    #[default]
    Argon2id = 3,
    #[cfg(feature = "ssh-agent")]
    SSHAgent = 4,
}

impl KeyDerivationMethod {
    /// Returns the zero-based index of the key derivation method.
    pub fn index(&self) -> usize { *self as usize }

    /// Attempts to create a `KeyDerivationMethod` from a zero-based index.
    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(KeyDerivationMethod::HKDF),
            1 => Some(KeyDerivationMethod::PBKDF2),
            2 => Some(KeyDerivationMethod::Scrypt),
            3 => Some(KeyDerivationMethod::Argon2id),
            #[cfg(feature = "ssh-agent")]
            4 => Some(KeyDerivationMethod::SSHAgent),
            _ => None,
        }
    }
}

impl std::fmt::Display for KeyDerivationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDerivationMethod::HKDF => write!(f, "HKDF"),
            KeyDerivationMethod::PBKDF2 => write!(f, "PBKDF2"),
            KeyDerivationMethod::Scrypt => write!(f, "Scrypt"),
            KeyDerivationMethod::Argon2id => write!(f, "Argon2id"),
            #[cfg(feature = "ssh-agent")]
            KeyDerivationMethod::SSHAgent => write!(f, "SSHAgent"),
        }
    }
}

impl TryFrom<&CBOR> for KeyDerivationMethod {
    type Error = Error;

    fn try_from(cbor: &CBOR) -> Result<Self> {
        let i: usize = cbor.clone().try_into()?;
        KeyDerivationMethod::from_index(i)
            .ok_or_else(|| Error::general("Invalid KeyDerivationMethod"))
    }
}
