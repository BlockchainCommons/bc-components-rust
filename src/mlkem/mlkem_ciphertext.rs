use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::Ciphertext;

use crate::tags;

use super::MLKEM;

#[derive(Clone, PartialEq)]
pub enum MLKEMCiphertext {
    MLKEM512(Box<mlkem512::Ciphertext>),
    MLKEM768(Box<mlkem768::Ciphertext>),
    MLKEM1024(Box<mlkem1024::Ciphertext>),
}

impl MLKEMCiphertext {
    pub fn level(&self) -> MLKEM {
        match self {
            MLKEMCiphertext::MLKEM512(_) => MLKEM::MLKEM512,
            MLKEMCiphertext::MLKEM768(_) => MLKEM::MLKEM768,
            MLKEMCiphertext::MLKEM1024(_) => MLKEM::MLKEM1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().ciphertext_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLKEMCiphertext::MLKEM512(ct) => ct.as_ref().as_bytes(),
            MLKEMCiphertext::MLKEM768(ct) => ct.as_ref().as_bytes(),
            MLKEMCiphertext::MLKEM1024(ct) => ct.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: MLKEM, bytes: &[u8]) -> Result<Self> {
        match level {
            MLKEM::MLKEM512 => Ok(MLKEMCiphertext::MLKEM512(Box::new(
                mlkem512::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLKEM::MLKEM768 => Ok(MLKEMCiphertext::MLKEM768(Box::new(
                mlkem768::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLKEM::MLKEM1024 => Ok(MLKEMCiphertext::MLKEM1024(Box::new(
                mlkem1024::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }
}

impl std::fmt::Debug for MLKEMCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLKEMCiphertext::MLKEM512(_) => f.write_str("MLKEM512Ciphertext"),
            MLKEMCiphertext::MLKEM768(_) => f.write_str("MLKEM768Ciphertext"),
            MLKEMCiphertext::MLKEM1024(_) => f.write_str("MLKEM1024Ciphertext"),
        }
    }
}

impl CBORTagged for MLKEMCiphertext {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLKEM_CIPHERTEXT])
    }
}

impl From<MLKEMCiphertext> for CBOR {
    fn from(value: MLKEMCiphertext) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for MLKEMCiphertext {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for MLKEMCiphertext {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for MLKEMCiphertext {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("MLKEMCiphertext must have two elements");
                }

                let level = MLKEM::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                MLKEMCiphertext::from_bytes(level, &data)
            }
            _ => bail!("MLKEMCiphertext must be an array"),
        }
    }
}
