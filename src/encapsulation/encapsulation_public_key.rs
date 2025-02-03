use anyhow::{Result, bail};
use dcbor::prelude::*;
use crate::{Encrypter, KyberPublicKey};

use crate::{tags, X25519PublicKey, EncapsulationScheme, EncapsulationCiphertext, PrivateKeyBase, SymmetricKey};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncapsulationPublicKey {
    X25519(X25519PublicKey),
    Kyber(KyberPublicKey),
}

impl EncapsulationPublicKey {
    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        match self {
            Self::X25519(_) => EncapsulationScheme::X25519,
            Self::Kyber(pk) => {
                match pk.level() {
                    crate::Kyber::Kyber512 => EncapsulationScheme::Kyber512,
                    crate::Kyber::Kyber768 => EncapsulationScheme::Kyber768,
                    crate::Kyber::Kyber1024 => EncapsulationScheme::Kyber1024,
                }
            }
        }
    }

    pub fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, EncapsulationCiphertext) {
        match self {
            EncapsulationPublicKey::X25519(public_key) => {
                let emphemeral_sender = PrivateKeyBase::new();
                let ephemeral_private_key = emphemeral_sender.x25519_private_key();
                let ephemeral_public_key = ephemeral_private_key.public_key();
                let shared_key = ephemeral_private_key.shared_key_with(public_key);
                (shared_key, EncapsulationCiphertext::X25519(ephemeral_public_key))
            }
            EncapsulationPublicKey::Kyber(public_key) => {
                let (shared_key, ciphertext) = public_key.encapsulate_new_shared_secret();
                (shared_key, EncapsulationCiphertext::Kyber(ciphertext))
            }
        }
    }
}

impl Encrypter for EncapsulationPublicKey {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        self.clone()
    }

    fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, EncapsulationCiphertext) {
        self.encapsulate_new_shared_secret()
    }
}

impl From<EncapsulationPublicKey> for CBOR {
    fn from(ciphertext: EncapsulationPublicKey) -> Self {
        match ciphertext {
            EncapsulationPublicKey::X25519(public_key) => public_key.into(),
            EncapsulationPublicKey::Kyber(ciphertext) => ciphertext.into(),
        }
    }
}

impl TryFrom<CBOR> for EncapsulationPublicKey {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => {
                match tag.value() {
                    tags::TAG_X25519_PUBLIC_KEY => Ok(EncapsulationPublicKey::X25519(X25519PublicKey::try_from(cbor)?)),
                    tags::TAG_KYBER_PUBLIC_KEY => Ok(EncapsulationPublicKey::Kyber(KyberPublicKey::try_from(cbor)?)),
                    _ => bail!("Invalid encapsulation public key")
                }
            }
            _ => bail!("Invalid encapsulation public key")
        }
    }
}
