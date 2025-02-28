use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use crate::tags;

use super::{MLDSASignature, MLDSA};

#[derive(Clone, PartialEq)]
pub enum MLDSAPrivateKey {
    MLDSA44(Box<mldsa44::SecretKey>),
    MLDSA65(Box<mldsa65::SecretKey>),
    MLDSA87(Box<mldsa87::SecretKey>),
}

impl MLDSAPrivateKey {
    pub fn sign(&self, message: impl AsRef<[u8]>) -> MLDSASignature {
        match self {
            MLDSAPrivateKey::MLDSA44(sk) => {
                MLDSASignature::MLDSA44(Box::new(mldsa44::detached_sign(message.as_ref(), sk)))
            }
            MLDSAPrivateKey::MLDSA65(sk) => {
                MLDSASignature::MLDSA65(Box::new(mldsa65::detached_sign(message.as_ref(), sk)))
            }
            MLDSAPrivateKey::MLDSA87(sk) => {
                MLDSASignature::MLDSA87(Box::new(mldsa87::detached_sign(message.as_ref(), sk)))
            }
        }
    }

    pub fn level(&self) -> MLDSA {
        match self {
            MLDSAPrivateKey::MLDSA44(_) => MLDSA::MLDSA44,
            MLDSAPrivateKey::MLDSA65(_) => MLDSA::MLDSA65,
            MLDSAPrivateKey::MLDSA87(_) => MLDSA::MLDSA87,
        }
    }

    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLDSAPrivateKey::MLDSA44(key) => key.as_bytes(),
            MLDSAPrivateKey::MLDSA65(key) => key.as_bytes(),
            MLDSAPrivateKey::MLDSA87(key) => key.as_bytes(),
        }
    }

    pub fn from_bytes(level: MLDSA, bytes: &[u8]) -> Result<Self> {
        match level {
            MLDSA::MLDSA44 => Ok(MLDSAPrivateKey::MLDSA44(Box::new(
                mldsa44::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLDSA::MLDSA65 => Ok(MLDSAPrivateKey::MLDSA65(Box::new(
                mldsa65::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLDSA::MLDSA87 => Ok(MLDSAPrivateKey::MLDSA87(Box::new(
                mldsa87::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }
}

impl std::fmt::Debug for MLDSAPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLDSAPrivateKey::MLDSA44(_) => f.write_str("MLDSA44PrivateKey"),
            MLDSAPrivateKey::MLDSA65(_) => f.write_str("MLDSA65PrivateKey"),
            MLDSAPrivateKey::MLDSA87(_) => f.write_str("MLDSA87PrivateKey"),
        }
    }
}

impl CBORTagged for MLDSAPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLDSA_PRIVATE_KEY])
    }
}

impl From<MLDSAPrivateKey> for CBOR {
    fn from(value: MLDSAPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for MLDSAPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for MLDSAPrivateKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for MLDSAPrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("MLDSAPrivateKey must have two elements");
                }

                let level = MLDSA::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                MLDSAPrivateKey::from_bytes(level, &data)
            }
            _ => bail!("MLDSAPrivateKey must be an array"),
        }
    }
}
