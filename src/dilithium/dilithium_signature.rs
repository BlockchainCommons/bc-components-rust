use anyhow::{Result, Error, anyhow, bail};
use dcbor::prelude::*;
use pqcrypto_dilithium::*;
use pqcrypto_traits::sign::*;

use crate::tags;

use super::Dilithium;

#[derive(Clone)]
pub enum DilithiumSignature {
    Dilithium2(Box<dilithium2::DetachedSignature>),
    Dilithium3(Box<dilithium3::DetachedSignature>),
    Dilithium5(Box<dilithium5::DetachedSignature>),
}

impl DilithiumSignature {
    pub fn level(&self) -> Dilithium {
        match self {
            DilithiumSignature::Dilithium2(_) => Dilithium::Dilithium2,
            DilithiumSignature::Dilithium3(_) => Dilithium::Dilithium3,
            DilithiumSignature::Dilithium5(_) => Dilithium::Dilithium5,
        }
    }

    pub fn size(&self) -> usize {
        self.level().signature_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumSignature::Dilithium2(sig) => sig.as_bytes(),
            DilithiumSignature::Dilithium3(sig) => sig.as_bytes(),
            DilithiumSignature::Dilithium5(sig) => sig.as_bytes(),
        }
    }

    pub fn from_bytes(level: Dilithium, bytes: &[u8]) -> Result<Self> {
        match level {
            Dilithium::Dilithium2 => Ok(DilithiumSignature::Dilithium2(Box::new(dilithium2::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Dilithium::Dilithium3 => Ok(DilithiumSignature::Dilithium3(Box::new(dilithium3::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Dilithium::Dilithium5 => Ok(DilithiumSignature::Dilithium5(Box::new(dilithium5::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumSignature::Dilithium2(_) => f.write_str("Dilithium2Signature"),
            DilithiumSignature::Dilithium3(_) => f.write_str("Dilithium3Signature"),
            DilithiumSignature::Dilithium5(_) => f.write_str("Dilithium5Signature"),
        }
    }
}

impl CBORTagged for DilithiumSignature {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_DILITHIUM_SIGNATURE])
    }
}

impl From<DilithiumSignature> for CBOR {
    fn from(value: DilithiumSignature) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for DilithiumSignature {
    fn untagged_cbor(&self) -> CBOR {
        vec![
            self.level().into(),
            CBOR::to_byte_string(self.as_bytes())
        ].into()
    }
}

impl TryFrom<CBOR> for DilithiumSignature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for DilithiumSignature {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("DilithiumSignature must have two elements");
                }

                let level = Dilithium::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                DilithiumSignature::from_bytes(level, &data)
            }
            _ => bail!("DilithiumSignature must be an array"),
        }
    }
}
