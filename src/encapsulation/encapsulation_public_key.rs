use crate::{Encrypter, MLKEMPublicKey};
use anyhow::{bail, Result};
use dcbor::prelude::*;

use crate::{
    tags, EncapsulationCiphertext, EncapsulationScheme, PrivateKeyBase, SymmetricKey,
    X25519PublicKey,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncapsulationPublicKey {
    X25519(X25519PublicKey),
    MLKEM(MLKEMPublicKey),
}

impl EncapsulationPublicKey {
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

    pub fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, EncapsulationCiphertext) {
        match self {
            EncapsulationPublicKey::X25519(public_key) => {
                let emphemeral_sender = PrivateKeyBase::new();
                let ephemeral_private_key = emphemeral_sender.x25519_private_key();
                let ephemeral_public_key = ephemeral_private_key.public_key();
                let shared_key = ephemeral_private_key.shared_key_with(public_key);
                (
                    shared_key,
                    EncapsulationCiphertext::X25519(ephemeral_public_key),
                )
            }
            EncapsulationPublicKey::MLKEM(public_key) => {
                let (shared_key, ciphertext) = public_key.encapsulate_new_shared_secret();
                (shared_key, EncapsulationCiphertext::MLKEM(ciphertext))
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
            EncapsulationPublicKey::MLKEM(ciphertext) => ciphertext.into(),
        }
    }
}

impl TryFrom<CBOR> for EncapsulationPublicKey {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Tagged(tag, _) => match tag.value() {
                tags::TAG_X25519_PUBLIC_KEY => Ok(EncapsulationPublicKey::X25519(
                    X25519PublicKey::try_from(cbor)?,
                )),
                tags::TAG_MLKEM_PUBLIC_KEY => Ok(EncapsulationPublicKey::MLKEM(
                    MLKEMPublicKey::try_from(cbor)?,
                )),
                _ => bail!("Invalid encapsulation public key"),
            },
            _ => bail!("Invalid encapsulation public key"),
        }
    }
}
