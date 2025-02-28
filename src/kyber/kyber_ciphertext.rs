use anyhow::{Result, Error, anyhow, bail};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::Ciphertext;

use crate::tags;

use super::Kyber;

#[derive(Clone, PartialEq)]
pub enum KyberCiphertext {
    Kyber512(Box<mlkem512::Ciphertext>),
    Kyber768(Box<mlkem768::Ciphertext>),
    Kyber1024(Box<mlkem1024::Ciphertext>),
}

impl KyberCiphertext {
    pub fn level(&self) -> Kyber {
        match self {
            KyberCiphertext::Kyber512(_) => Kyber::Kyber512,
            KyberCiphertext::Kyber768(_) => Kyber::Kyber768,
            KyberCiphertext::Kyber1024(_) => Kyber::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().ciphertext_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberCiphertext::Kyber512(ct) => ct.as_ref().as_bytes(),
            KyberCiphertext::Kyber768(ct) => ct.as_ref().as_bytes(),
            KyberCiphertext::Kyber1024(ct) => ct.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: Kyber, bytes: &[u8]) -> Result<Self> {
        match level {
            Kyber::Kyber512 => Ok(KyberCiphertext::Kyber512(Box::new(mlkem512::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Kyber::Kyber768 => Ok(KyberCiphertext::Kyber768(Box::new(mlkem768::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Kyber::Kyber1024 => Ok(KyberCiphertext::Kyber1024(Box::new(mlkem1024::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for KyberCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberCiphertext::Kyber512(_) => f.write_str("Kyber512Ciphertext"),
            KyberCiphertext::Kyber768(_) => f.write_str("Kyber768Ciphertext"),
            KyberCiphertext::Kyber1024(_) => f.write_str("Kyber1024Ciphertext"),
        }
    }
}

impl CBORTagged for KyberCiphertext {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_KYBER_CIPHERTEXT])
    }
}

impl From<KyberCiphertext> for CBOR {
    fn from(value: KyberCiphertext) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for KyberCiphertext {
    fn untagged_cbor(&self) -> CBOR {
        vec![
            self.level().into(),
            CBOR::to_byte_string(self.as_bytes())
        ].into()
    }
}

impl TryFrom<CBOR> for KyberCiphertext {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for KyberCiphertext {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("KyberCiphertext must have two elements");
                }

                let level = Kyber::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                KyberCiphertext::from_bytes(level, &data)
            }
            _ => bail!("KyberCiphertext must be an array"),
        }
    }
}
