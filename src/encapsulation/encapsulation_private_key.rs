use crate::{Decrypter, MLKEMPrivateKey};
use anyhow::{bail, Result};
use dcbor::prelude::*;

use crate::{tags, EncapsulationCiphertext, EncapsulationScheme, SymmetricKey, X25519PrivateKey};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncapsulationPrivateKey {
    X25519(X25519PrivateKey),
    MLKEM(MLKEMPrivateKey),
}

impl EncapsulationPrivateKey {
    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            Self::MLKEM(pk) => match pk.level() {
                crate::MLKEM::MLKEM512 => EncapsulationScheme::MLKEM512,
                crate::MLKEM::MLKEM768 => EncapsulationScheme::MLKEM768,
                crate::MLKEM::MLKEM1024 => EncapsulationScheme::MLKEM1024,
            },
        }
    }

    pub fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey> {
        match (self, ciphertext) {
            (
                EncapsulationPrivateKey::X25519(private_key),
                EncapsulationCiphertext::X25519(public_key),
            ) => Ok(private_key.shared_key_with(public_key)),
            (
                EncapsulationPrivateKey::MLKEM(private_key),
                EncapsulationCiphertext::MLKEM(ciphertext),
            ) => private_key.decapsulate_shared_secret(ciphertext),
            _ => bail!(
                "Mismatched key encapsulation types. private key: {:?}, ciphertext: {:?}",
                self.encapsulation_scheme(),
                ciphertext.encapsulation_scheme()
            ),
        }
    }
}

impl Decrypter for EncapsulationPrivateKey {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.clone()
    }

    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey> {
        self.decapsulate_shared_secret(ciphertext)
    }
}

impl From<EncapsulationPrivateKey> for CBOR {
    fn from(ciphertext: EncapsulationPrivateKey) -> Self {
        match ciphertext {
            EncapsulationPrivateKey::X25519(public_key) => public_key.into(),
            EncapsulationPrivateKey::MLKEM(ciphertext) => ciphertext.into(),
        }
    }
}

impl TryFrom<CBOR> for EncapsulationPrivateKey {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => match tag.value() {
                tags::TAG_X25519_PRIVATE_KEY => Ok(EncapsulationPrivateKey::X25519(
                    X25519PrivateKey::try_from(cbor)?,
                )),
                tags::TAG_MLKEM_PRIVATE_KEY => Ok(EncapsulationPrivateKey::MLKEM(
                    MLKEMPrivateKey::try_from(cbor)?,
                )),
                _ => bail!("Invalid encapsulation private key"),
            },
            _ => bail!("Invalid encapsulation private key"),
        }
    }
}
