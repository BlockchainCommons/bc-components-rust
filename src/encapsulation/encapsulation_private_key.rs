use anyhow::{Result, bail};
use dcbor::prelude::*;
use crate::{Decrypter, KyberPrivateKey};

use crate::{tags, X25519PrivateKey, Encapsulation, EncapsulationCiphertext, SymmetricKey};

#[derive(Debug, Clone, PartialEq)]
pub enum EncapsulationPrivateKey {
    X25519(X25519PrivateKey),
    Kyber(KyberPrivateKey),
}

impl EncapsulationPrivateKey {
    pub fn encapsulation_type(&self) -> Encapsulation {
        match self {
            Self::X25519(_) => Encapsulation::X25519,
            Self::Kyber(pk) => Encapsulation::Kyber(pk.level()),
        }
    }

    pub fn decapsulate_shared_secret(&self, ciphertext: &EncapsulationCiphertext) -> Result<SymmetricKey> {
        match (self, ciphertext) {
            (EncapsulationPrivateKey::X25519(private_key), EncapsulationCiphertext::X25519(public_key)) => {
                Ok(private_key.shared_key_with(public_key))
            }
            (EncapsulationPrivateKey::Kyber(private_key), EncapsulationCiphertext::Kyber(ciphertext)) => {
                private_key.decapsulate_shared_secret(ciphertext)
            }
            _ => bail!("Mismatched key encapsulation types. private key: {:?}, ciphertext: {:?}", self.encapsulation_type(), ciphertext.encapsulation_type()),
        }
    }
}

impl Decrypter for EncapsulationPrivateKey {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.clone()
    }

    fn decapsulate_shared_secret(&self, ciphertext: &EncapsulationCiphertext) -> Result<SymmetricKey> {
        self.decapsulate_shared_secret(ciphertext)
    }
}

impl From<EncapsulationPrivateKey> for CBOR {
    fn from(ciphertext: EncapsulationPrivateKey) -> Self {
        match ciphertext {
            EncapsulationPrivateKey::X25519(public_key) => public_key.into(),
            EncapsulationPrivateKey::Kyber(ciphertext) => ciphertext.into(),
        }
    }
}

impl TryFrom<CBOR> for EncapsulationPrivateKey {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => {
                match tag.value() {
                    tags::TAG_X25519_PRIVATE_KEY => Ok(EncapsulationPrivateKey::X25519(X25519PrivateKey::try_from(cbor)?)),
                    tags::TAG_KYBER_PRIVATE_KEY => Ok(EncapsulationPrivateKey::Kyber(KyberPrivateKey::try_from(cbor)?)),
                    _ => bail!("Invalid encapsulation private key")
                }
            }
            _ => bail!("Invalid encapsulation private key")
        }
    }
}
