use crate::{tags, MLKEMCiphertext};
use anyhow::{bail, Result};
use dcbor::prelude::*;

use crate::{EncapsulationScheme, X25519PublicKey};

#[derive(Debug, Clone, PartialEq)]
pub enum EncapsulationCiphertext {
    X25519(X25519PublicKey),
    MLKEM(MLKEMCiphertext),
}

impl EncapsulationCiphertext {
    pub fn x25519_public_key(&self) -> Result<&X25519PublicKey> {
        match self {
            Self::X25519(public_key) => Ok(public_key),
            _ => bail!("Invalid key encapsulation type"),
        }
    }

    pub fn mlkem_ciphertext(&self) -> Result<&MLKEMCiphertext> {
        match self {
            Self::MLKEM(ciphertext) => Ok(ciphertext),
            _ => bail!("Invalid key encapsulation type"),
        }
    }

    pub fn is_x25519(&self) -> bool {
        matches!(self, Self::X25519(_))
    }

    pub fn is_mlkem(&self) -> bool {
        matches!(self, Self::MLKEM(_))
    }

    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            Self::MLKEM(ct) => match ct.level() {
                crate::MLKEM::MLKEM512 => EncapsulationScheme::MLKEM512,
                crate::MLKEM::MLKEM768 => EncapsulationScheme::MLKEM768,
                crate::MLKEM::MLKEM1024 => EncapsulationScheme::MLKEM1024,
            },
        }
    }
}

impl From<EncapsulationCiphertext> for CBOR {
    fn from(ciphertext: EncapsulationCiphertext) -> Self {
        match ciphertext {
            EncapsulationCiphertext::X25519(public_key) => public_key.into(),
            EncapsulationCiphertext::MLKEM(ciphertext) => ciphertext.into(),
        }
    }
}

impl TryFrom<CBOR> for EncapsulationCiphertext {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => match tag.value() {
                tags::TAG_X25519_PUBLIC_KEY => Ok(EncapsulationCiphertext::X25519(
                    X25519PublicKey::try_from(cbor)?,
                )),
                tags::TAG_MLKEM_CIPHERTEXT => Ok(EncapsulationCiphertext::MLKEM(
                    MLKEMCiphertext::try_from(cbor)?,
                )),
                _ => bail!("Invalid encapsulation ciphertext"),
            },
            _ => bail!("Invalid encapsulation ciphertext"),
        }
    }
}
