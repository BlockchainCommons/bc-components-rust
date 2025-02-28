use anyhow::{Result, Error, anyhow, bail};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::*;

use crate::tags;

use super::{Dilithium, DilithiumSignature};

#[derive(Clone, PartialEq)]
pub enum DilithiumPrivateKey {
    Dilithium2(Box<mldsa44::SecretKey>),
    Dilithium3(Box<mldsa65::SecretKey>),
    Dilithium5(Box<mldsa87::SecretKey>),
}

impl DilithiumPrivateKey {
    pub fn sign(&self, message: impl AsRef<[u8]>) -> DilithiumSignature {
        match self {
            DilithiumPrivateKey::Dilithium2(sk) => DilithiumSignature::Dilithium2(Box::new(mldsa44::detached_sign(message.as_ref(), sk))),
            DilithiumPrivateKey::Dilithium3(sk) => DilithiumSignature::Dilithium3(Box::new(mldsa65::detached_sign(message.as_ref(), sk))),
            DilithiumPrivateKey::Dilithium5(sk) => DilithiumSignature::Dilithium5(Box::new(mldsa87::detached_sign(message.as_ref(), sk))),
        }
    }

    pub fn level(&self) -> Dilithium {
        match self {
            DilithiumPrivateKey::Dilithium2(_) => Dilithium::Dilithium2,
            DilithiumPrivateKey::Dilithium3(_) => Dilithium::Dilithium3,
            DilithiumPrivateKey::Dilithium5(_) => Dilithium::Dilithium5,
        }
    }

    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumPrivateKey::Dilithium2(key) => key.as_bytes(),
            DilithiumPrivateKey::Dilithium3(key) => key.as_bytes(),
            DilithiumPrivateKey::Dilithium5(key) => key.as_bytes(),
        }
    }

    pub fn from_bytes(level: Dilithium, bytes: &[u8]) -> Result<Self> {
        match level {
            Dilithium::Dilithium2 => Ok(DilithiumPrivateKey::Dilithium2(Box::new(mldsa44::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Dilithium::Dilithium3 => Ok(DilithiumPrivateKey::Dilithium3(Box::new(mldsa65::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Dilithium::Dilithium5 => Ok(DilithiumPrivateKey::Dilithium5(Box::new(mldsa87::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for DilithiumPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumPrivateKey::Dilithium2(_) => f.write_str("Dilithium2PrivateKey"),
            DilithiumPrivateKey::Dilithium3(_) => f.write_str("Dilithium3PrivateKey"),
            DilithiumPrivateKey::Dilithium5(_) => f.write_str("Dilithium5PrivateKey"),
        }
    }
}

impl CBORTagged for DilithiumPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_DILITHIUM_PRIVATE_KEY])
    }
}

impl From<DilithiumPrivateKey> for CBOR {
    fn from(value: DilithiumPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for DilithiumPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![
            self.level().into(),
            CBOR::to_byte_string(self.as_bytes())
        ].into()
    }
}

impl TryFrom<CBOR> for DilithiumPrivateKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for DilithiumPrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("DilithiumPrivateKey must have two elements");
                }

                let level = Dilithium::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                DilithiumPrivateKey::from_bytes(level, &data)
            }
            _ => bail!("DilithiumPrivateKey must be an array"),
        }
    }
}
