use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::{PublicKey, SharedSecret};

use crate::{tags, SymmetricKey};

use super::{MLKEMCiphertext, MLKEM};

#[derive(Clone)]
pub enum MLKEMPublicKey {
    MLKEM512(Box<mlkem512::PublicKey>),
    MLKEM768(Box<mlkem768::PublicKey>),
    MLKEM1024(Box<mlkem1024::PublicKey>),
}

impl PartialEq for MLKEMPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for MLKEMPublicKey {}

impl std::hash::Hash for MLKEMPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.level().hash(state);
        self.as_bytes().hash(state);
    }
}

impl MLKEMPublicKey {
    pub fn level(&self) -> MLKEM {
        match self {
            MLKEMPublicKey::MLKEM512(_) => MLKEM::MLKEM512,
            MLKEMPublicKey::MLKEM768(_) => MLKEM::MLKEM768,
            MLKEMPublicKey::MLKEM1024(_) => MLKEM::MLKEM1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().public_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLKEMPublicKey::MLKEM512(pk) => pk.as_ref().as_bytes(),
            MLKEMPublicKey::MLKEM768(pk) => pk.as_ref().as_bytes(),
            MLKEMPublicKey::MLKEM1024(pk) => pk.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: MLKEM, bytes: &[u8]) -> Result<Self> {
        match level {
            MLKEM::MLKEM512 => Ok(MLKEMPublicKey::MLKEM512(Box::new(
                mlkem512::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLKEM::MLKEM768 => Ok(MLKEMPublicKey::MLKEM768(Box::new(
                mlkem768::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLKEM::MLKEM1024 => Ok(MLKEMPublicKey::MLKEM1024(Box::new(
                mlkem1024::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }

    pub fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, MLKEMCiphertext) {
        match self {
            MLKEMPublicKey::MLKEM512(pk) => {
                let (ss, ct) = mlkem512::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    MLKEMCiphertext::MLKEM512(ct.into()),
                )
            }
            MLKEMPublicKey::MLKEM768(pk) => {
                let (ss, ct) = mlkem768::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    MLKEMCiphertext::MLKEM768(ct.into()),
                )
            }
            MLKEMPublicKey::MLKEM1024(pk) => {
                let (ss, ct) = mlkem1024::encapsulate(pk.as_ref());
                (
                    SymmetricKey::from_data_ref(ss.as_bytes()).unwrap(),
                    MLKEMCiphertext::MLKEM1024(ct.into()),
                )
            }
        }
    }
}

impl std::fmt::Debug for MLKEMPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLKEMPublicKey::MLKEM512(_) => f.write_str("MLKEM512PublicKey"),
            MLKEMPublicKey::MLKEM768(_) => f.write_str("MLKEM768PublicKey"),
            MLKEMPublicKey::MLKEM1024(_) => f.write_str("MLKEM1024PublicKey"),
        }
    }
}

impl CBORTagged for MLKEMPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLKEM_PUBLIC_KEY])
    }
}

impl From<MLKEMPublicKey> for CBOR {
    fn from(value: MLKEMPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for MLKEMPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for MLKEMPublicKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for MLKEMPublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("MLKEMPublicKey must have two elements");
                }

                let level = MLKEM::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                MLKEMPublicKey::from_bytes(level, &data)
            }
            _ => bail!("MLKEMPublicKey must be an array"),
        }
    }
}
