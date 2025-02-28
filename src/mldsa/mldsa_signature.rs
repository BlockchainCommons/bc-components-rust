use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use crate::tags;

use super::MLDSA;

#[derive(Clone)]
pub enum MLDSASignature {
    MLDSA44(Box<mldsa44::DetachedSignature>),
    MLDSA65(Box<mldsa65::DetachedSignature>),
    MLDSA87(Box<mldsa87::DetachedSignature>),
}

impl PartialEq for MLDSASignature {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl MLDSASignature {
    pub fn level(&self) -> MLDSA {
        match self {
            MLDSASignature::MLDSA44(_) => MLDSA::MLDSA44,
            MLDSASignature::MLDSA65(_) => MLDSA::MLDSA65,
            MLDSASignature::MLDSA87(_) => MLDSA::MLDSA87,
        }
    }

    pub fn size(&self) -> usize {
        self.level().signature_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLDSASignature::MLDSA44(sig) => sig.as_bytes(),
            MLDSASignature::MLDSA65(sig) => sig.as_bytes(),
            MLDSASignature::MLDSA87(sig) => sig.as_bytes(),
        }
    }

    pub fn from_bytes(level: MLDSA, bytes: &[u8]) -> Result<Self> {
        match level {
            MLDSA::MLDSA44 => Ok(MLDSASignature::MLDSA44(Box::new(
                mldsa44::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLDSA::MLDSA65 => Ok(MLDSASignature::MLDSA65(Box::new(
                mldsa65::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLDSA::MLDSA87 => Ok(MLDSASignature::MLDSA87(Box::new(
                mldsa87::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }
}

impl std::fmt::Debug for MLDSASignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLDSASignature::MLDSA44(_) => f.write_str("MLDSA44Signature"),
            MLDSASignature::MLDSA65(_) => f.write_str("MLDSA65Signature"),
            MLDSASignature::MLDSA87(_) => f.write_str("MLDSA87Signature"),
        }
    }
}

impl CBORTagged for MLDSASignature {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLDSA_SIGNATURE])
    }
}

impl From<MLDSASignature> for CBOR {
    fn from(value: MLDSASignature) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for MLDSASignature {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for MLDSASignature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for MLDSASignature {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("MLDSASignature must have two elements");
                }

                let level = MLDSA::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                MLDSASignature::from_bytes(level, &data)
            }
            _ => bail!("MLDSASignature must be an array"),
        }
    }
}
