use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use crate::tags;

use super::{MLDSASignature, MLDSA};

#[derive(Clone)]
pub enum MLDSAPublicKey {
    MLDSA44(Box<mldsa44::PublicKey>),
    MLDSA65(Box<mldsa65::PublicKey>),
    MLDSA87(Box<mldsa87::PublicKey>),
}

impl PartialEq for MLDSAPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for MLDSAPublicKey {}

impl std::hash::Hash for MLDSAPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.level().hash(state);
        self.as_bytes().hash(state);
    }
}

impl MLDSAPublicKey {
    pub fn verify(&self, signature: &MLDSASignature, message: impl AsRef<[u8]>) -> Result<bool> {
        if signature.level() != self.level() {
            bail!("Signature level does not match public key level");
        }

        let verifies = match (self, signature) {
            (MLDSAPublicKey::MLDSA44(pk), MLDSASignature::MLDSA44(sig)) => {
                mldsa44::verify_detached_signature(sig, message.as_ref(), pk).is_ok()
            }
            (MLDSAPublicKey::MLDSA65(pk), MLDSASignature::MLDSA65(sig)) => {
                mldsa65::verify_detached_signature(sig, message.as_ref(), pk).is_ok()
            }
            (MLDSAPublicKey::MLDSA87(pk), MLDSASignature::MLDSA87(sig)) => {
                mldsa87::verify_detached_signature(sig, message.as_ref(), pk).is_ok()
            }
            _ => false,
        };

        Ok(verifies)
    }

    pub fn level(&self) -> MLDSA {
        match self {
            MLDSAPublicKey::MLDSA44(_) => MLDSA::MLDSA44,
            MLDSAPublicKey::MLDSA65(_) => MLDSA::MLDSA65,
            MLDSAPublicKey::MLDSA87(_) => MLDSA::MLDSA87,
        }
    }

    pub fn size(&self) -> usize {
        self.level().public_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLDSAPublicKey::MLDSA44(key) => key.as_bytes(),
            MLDSAPublicKey::MLDSA65(key) => key.as_bytes(),
            MLDSAPublicKey::MLDSA87(key) => key.as_bytes(),
        }
    }

    pub fn from_bytes(level: MLDSA, bytes: &[u8]) -> Result<Self> {
        match level {
            MLDSA::MLDSA44 => Ok(MLDSAPublicKey::MLDSA44(Box::new(
                mldsa44::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLDSA::MLDSA65 => Ok(MLDSAPublicKey::MLDSA65(Box::new(
                mldsa65::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLDSA::MLDSA87 => Ok(MLDSAPublicKey::MLDSA87(Box::new(
                mldsa87::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }
}

impl std::fmt::Debug for MLDSAPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLDSAPublicKey::MLDSA44(_) => f.write_str("MLDSA442PublicKey"),
            MLDSAPublicKey::MLDSA65(_) => f.write_str("MLDSA65PublicKey"),
            MLDSAPublicKey::MLDSA87(_) => f.write_str("MLDSA87PublicKey"),
        }
    }
}

impl CBORTagged for MLDSAPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLDSA_PUBLIC_KEY])
    }
}

impl From<MLDSAPublicKey> for CBOR {
    fn from(value: MLDSAPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for MLDSAPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for MLDSAPublicKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for MLDSAPublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("MLDSAPublicKey must have two elements");
                }

                let level = MLDSA::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                MLDSAPublicKey::from_bytes(level, &data)
            }
            _ => bail!("MLDSAPublicKey must be an array"),
        }
    }
}
