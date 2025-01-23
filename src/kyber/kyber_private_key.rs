use anyhow::{Result, Error, anyhow, bail};
use dcbor::prelude::*;
use pqcrypto_kyber::*;
use pqcrypto_traits::kem::{SecretKey, SharedSecret};

use crate::{tags, SymmetricKey};

use super::{Kyber, KyberCiphertext};

#[derive(Clone, PartialEq)]
pub enum KyberPrivateKey {
    Kyber512(Box<kyber512::SecretKey>),
    Kyber768(Box<kyber768::SecretKey>),
    Kyber1024(Box<kyber1024::SecretKey>),
}

impl KyberPrivateKey {
    pub fn level(&self) -> Kyber {
        match self {
            KyberPrivateKey::Kyber512(_) => Kyber::Kyber512,
            KyberPrivateKey::Kyber768(_) => Kyber::Kyber768,
            KyberPrivateKey::Kyber1024(_) => Kyber::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberPrivateKey::Kyber512(sk) => sk.as_ref().as_bytes(),
            KyberPrivateKey::Kyber768(sk) => sk.as_ref().as_bytes(),
            KyberPrivateKey::Kyber1024(sk) => sk.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: Kyber, bytes: &[u8]) -> Result<Self> {
        match level {
            Kyber::Kyber512 => Ok(KyberPrivateKey::Kyber512(Box::new(kyber512::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Kyber::Kyber768 => Ok(KyberPrivateKey::Kyber768(Box::new(kyber768::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Kyber::Kyber1024 => Ok(KyberPrivateKey::Kyber1024(Box::new(kyber1024::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }

    pub fn decapsulate_shared_secret(&self, ciphertext: &KyberCiphertext) -> Result<SymmetricKey> {
        match (self, ciphertext) {
            (KyberPrivateKey::Kyber512(sk), KyberCiphertext::Kyber512(ct)) => {
                let ss = kyber512::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            (KyberPrivateKey::Kyber768(sk), KyberCiphertext::Kyber768(ct)) => {
                let ss = kyber768::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            (KyberPrivateKey::Kyber1024(sk), KyberCiphertext::Kyber1024(ct)) => {
                let ss = kyber1024::decapsulate(ct.as_ref(), sk.as_ref());
                SymmetricKey::from_data_ref(ss.as_bytes())
            }
            _ => panic!("Kyber level mismatch"),
        }
    }
}

impl std::fmt::Debug for KyberPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberPrivateKey::Kyber512(_) => f.write_str("Kyber512PrivateKey"),
            KyberPrivateKey::Kyber768(_) => f.write_str("Kyber768PrivateKey"),
            KyberPrivateKey::Kyber1024(_) => f.write_str("Kyber1024PrivateKey"),
        }
    }
}

impl CBORTagged for KyberPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_KYBER_PRIVATE_KEY])
    }
}

impl From<KyberPrivateKey> for CBOR {
    fn from(value: KyberPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for KyberPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![
            self.level().into(),
            CBOR::to_byte_string(self.as_bytes())
        ].into()
    }
}

impl TryFrom<CBOR> for KyberPrivateKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for KyberPrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("KyberPrivateKey must have two elements");
                }

                let level = Kyber::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                KyberPrivateKey::from_bytes(level, &data)
            }
            _ => bail!("KyberPrivateKey must be an array"),
        }
    }
}
