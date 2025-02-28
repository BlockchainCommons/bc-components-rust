use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::{PublicKey, SharedSecret};

use crate::{tags, SymmetricKey};

use super::{Kyber, KyberCiphertext};

#[derive(Clone)]
pub enum KyberPublicKey {
    Kyber512(Box<mlkem512::PublicKey>),
    Kyber768(Box<mlkem768::PublicKey>),
    Kyber1024(Box<mlkem1024::PublicKey>),
}

impl PartialEq for KyberPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for KyberPublicKey {}

impl std::hash::Hash for KyberPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.level().hash(state);
        self.as_bytes().hash(state);
    }
}

impl KyberPublicKey {
    pub fn level(&self) -> Kyber {
        match self {
            KyberPublicKey::Kyber512(_) => Kyber::Kyber512,
            KyberPublicKey::Kyber768(_) => Kyber::Kyber768,
            KyberPublicKey::Kyber1024(_) => Kyber::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().public_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberPublicKey::Kyber512(pk) => pk.as_ref().as_bytes(),
            KyberPublicKey::Kyber768(pk) => pk.as_ref().as_bytes(),
            KyberPublicKey::Kyber1024(pk) => pk.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: Kyber, bytes: &[u8]) -> Result<Self> {
        match level {
            Kyber::Kyber512 => Ok(KyberPublicKey::Kyber512(Box::new(
                mlkem512::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            Kyber::Kyber768 => Ok(KyberPublicKey::Kyber768(Box::new(
                mlkem768::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            Kyber::Kyber1024 => Ok(KyberPublicKey::Kyber1024(Box::new(
                mlkem1024::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }

    pub fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, KyberCiphertext) {
        match self {
            KyberPublicKey::Kyber512(pk) => {
                let (ss, ct) = mlkem512::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    KyberCiphertext::Kyber512(ct.into()),
                )
            }
            KyberPublicKey::Kyber768(pk) => {
                let (ss, ct) = mlkem768::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    KyberCiphertext::Kyber768(ct.into()),
                )
            }
            KyberPublicKey::Kyber1024(pk) => {
                let (ss, ct) = mlkem1024::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    KyberCiphertext::Kyber1024(ct.into()),
                )
            }
        }
    }
}

impl std::fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberPublicKey::Kyber512(_) => f.write_str("Kyber512PublicKey"),
            KyberPublicKey::Kyber768(_) => f.write_str("Kyber768PublicKey"),
            KyberPublicKey::Kyber1024(_) => f.write_str("Kyber1024PublicKey"),
        }
    }
}

impl CBORTagged for KyberPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_KYBER_PUBLIC_KEY])
    }
}

impl From<KyberPublicKey> for CBOR {
    fn from(value: KyberPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for KyberPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for KyberPublicKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for KyberPublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("KyberPublicKey must have two elements");
                }

                let level = Kyber::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                KyberPublicKey::from_bytes(level, &data)
            }
            _ => bail!("KyberPublicKey must be an array"),
        }
    }
}
