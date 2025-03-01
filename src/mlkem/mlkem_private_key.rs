use anyhow::{anyhow, bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::{SecretKey, SharedSecret};

use crate::{tags, Decrypter, EncapsulationPrivateKey, SymmetricKey};

use super::{MLKEMCiphertext, MLKEM};

#[derive(Clone, PartialEq)]
pub enum MLKEMPrivateKey {
    MLKEM512(Box<mlkem512::SecretKey>),
    MLKEM768(Box<mlkem768::SecretKey>),
    MLKEM1024(Box<mlkem1024::SecretKey>),
}

impl Eq for MLKEMPrivateKey {}

impl std::hash::Hash for MLKEMPrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            MLKEMPrivateKey::MLKEM512(sk) => sk.as_bytes().hash(state),
            MLKEMPrivateKey::MLKEM768(sk) => sk.as_bytes().hash(state),
            MLKEMPrivateKey::MLKEM1024(sk) => sk.as_bytes().hash(state),
        }
    }
}

impl MLKEMPrivateKey {
    pub fn level(&self) -> MLKEM {
        match self {
            MLKEMPrivateKey::MLKEM512(_) => MLKEM::MLKEM512,
            MLKEMPrivateKey::MLKEM768(_) => MLKEM::MLKEM768,
            MLKEMPrivateKey::MLKEM1024(_) => MLKEM::MLKEM1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MLKEMPrivateKey::MLKEM512(sk) => sk.as_ref().as_bytes(),
            MLKEMPrivateKey::MLKEM768(sk) => sk.as_ref().as_bytes(),
            MLKEMPrivateKey::MLKEM1024(sk) => sk.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: MLKEM, bytes: &[u8]) -> Result<Self> {
        match level {
            MLKEM::MLKEM512 => Ok(MLKEMPrivateKey::MLKEM512(Box::new(
                mlkem512::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLKEM::MLKEM768 => Ok(MLKEMPrivateKey::MLKEM768(Box::new(
                mlkem768::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
            MLKEM::MLKEM1024 => Ok(MLKEMPrivateKey::MLKEM1024(Box::new(
                mlkem1024::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?,
            ))),
        }
    }

    pub fn decapsulate_shared_secret(&self, ciphertext: &MLKEMCiphertext) -> Result<SymmetricKey> {
        match (self, ciphertext) {
            (MLKEMPrivateKey::MLKEM512(sk), MLKEMCiphertext::MLKEM512(ct)) => {
                let ss = mlkem512::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            (MLKEMPrivateKey::MLKEM768(sk), MLKEMCiphertext::MLKEM768(ct)) => {
                let ss = mlkem768::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            (MLKEMPrivateKey::MLKEM1024(sk), MLKEMCiphertext::MLKEM1024(ct)) => {
                let ss = mlkem1024::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            _ => panic!("MLKEM level mismatch"),
        }
    }
}

impl Decrypter for MLKEMPrivateKey {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        EncapsulationPrivateKey::MLKEM(self.clone())
    }
}

impl std::fmt::Debug for MLKEMPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLKEMPrivateKey::MLKEM512(_) => f.write_str("MLKEM512PrivateKey"),
            MLKEMPrivateKey::MLKEM768(_) => f.write_str("MLKEM768PrivateKey"),
            MLKEMPrivateKey::MLKEM1024(_) => f.write_str("MLKEM1024PrivateKey"),
        }
    }
}

impl CBORTagged for MLKEMPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_MLKEM_PRIVATE_KEY])
    }
}

impl From<MLKEMPrivateKey> for CBOR {
    fn from(value: MLKEMPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for MLKEMPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![self.level().into(), CBOR::to_byte_string(self.as_bytes())].into()
    }
}

impl TryFrom<CBOR> for MLKEMPrivateKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for MLKEMPrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("MLKEMPrivateKey must have two elements");
                }

                let level = MLKEM::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                MLKEMPrivateKey::from_bytes(level, &data)
            }
            _ => bail!("MLKEMPrivateKey must be an array"),
        }
    }
}
