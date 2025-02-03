use anyhow::{ bail, Result };
use dcbor::prelude::*;
use crate::{tags, KyberCiphertext};

use crate::{X25519PublicKey, EncapsulationScheme};

#[derive(Debug, Clone, PartialEq)]
pub enum EncapsulationCiphertext {
    X25519(X25519PublicKey),
    Kyber(KyberCiphertext)
}

impl EncapsulationCiphertext {
    pub fn x25519_public_key(&self) -> Result<&X25519PublicKey> {
        match self {
            Self::X25519(public_key) => Ok(public_key),
            _ => bail!("Invalid key encapsulation type")
        }
    }

    pub fn kyber_ciphertext(&self) -> Result<&KyberCiphertext> {
        match self {
            Self::Kyber(ciphertext) => Ok(ciphertext),
            _ => bail!("Invalid key encapsulation type")
        }
    }

    pub fn is_x25519(&self) -> bool {
        matches!(self, Self::X25519(_))
    }

    pub fn is_kyber(&self) -> bool {
        matches!(self, Self::Kyber(_))
    }

    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            Self::Kyber(ct) => {
                match ct.level() {
                    crate::Kyber::Kyber512 => EncapsulationScheme::Kyber512,
                    crate::Kyber::Kyber768 => EncapsulationScheme::Kyber768,
                    crate::Kyber::Kyber1024 => EncapsulationScheme::Kyber1024,
                }
            }
        }
    }
}

impl From<EncapsulationCiphertext> for CBOR {
    fn from(ciphertext: EncapsulationCiphertext) -> Self {
        match ciphertext {
            EncapsulationCiphertext::X25519(public_key) => public_key.into(),
            EncapsulationCiphertext::Kyber(ciphertext) => ciphertext.into(),
        }
    }
}

impl TryFrom<CBOR> for EncapsulationCiphertext {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => {
                match tag.value() {
                    tags::TAG_X25519_PUBLIC_KEY => Ok(EncapsulationCiphertext::X25519(X25519PublicKey::try_from(cbor)?)),
                    tags::TAG_KYBER_CIPHERTEXT => Ok(EncapsulationCiphertext::Kyber(KyberCiphertext::try_from(cbor)?)),
                    _ => bail!("Invalid encapsulation ciphertext")
                }
            }
            _ => bail!("Invalid encapsulation ciphertext")
        }
    }
}
