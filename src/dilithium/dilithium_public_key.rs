use anyhow::{Result, Error, anyhow, bail};
use dcbor::prelude::*;
use pqcrypto_dilithium::*;
use pqcrypto_traits::sign::*;

use crate::tags;

use super::{Dilithium, DilithiumSignature};

#[derive(Clone)]
pub enum DilithiumPublicKey {
    Dilithium2(Box<dilithium2::PublicKey>),
    Dilithium3(Box<dilithium3::PublicKey>),
    Dilithium5(Box<dilithium5::PublicKey>),
}

impl PartialEq for DilithiumPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for DilithiumPublicKey {}

impl std::hash::Hash for DilithiumPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.level().hash(state);
        self.as_bytes().hash(state);
    }
}

impl DilithiumPublicKey {
    pub fn verify(&self, signature: &DilithiumSignature, message: impl AsRef<[u8]>) -> Result<bool> {
        if signature.level() != self.level() {
            bail!("Signature level does not match public key level");
        }

        let verifies = match (self, signature) {
            (DilithiumPublicKey::Dilithium2(pk), DilithiumSignature::Dilithium2(sig)) => dilithium2::verify_detached_signature(sig, message.as_ref(), pk).is_ok(),
            (DilithiumPublicKey::Dilithium3(pk), DilithiumSignature::Dilithium3(sig)) => dilithium3::verify_detached_signature(sig, message.as_ref(), pk).is_ok(),
            (DilithiumPublicKey::Dilithium5(pk), DilithiumSignature::Dilithium5(sig)) => dilithium5::verify_detached_signature(sig, message.as_ref(), pk).is_ok(),
            _ => false,
        };

        Ok(verifies)
    }

    pub fn level(&self) -> Dilithium {
        match self {
            DilithiumPublicKey::Dilithium2(_) => Dilithium::Dilithium2,
            DilithiumPublicKey::Dilithium3(_) => Dilithium::Dilithium3,
            DilithiumPublicKey::Dilithium5(_) => Dilithium::Dilithium5,
        }
    }

    pub fn size(&self) -> usize {
        self.level().public_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumPublicKey::Dilithium2(key) => key.as_bytes(),
            DilithiumPublicKey::Dilithium3(key) => key.as_bytes(),
            DilithiumPublicKey::Dilithium5(key) => key.as_bytes(),
        }
    }

    pub fn from_bytes(level: Dilithium, bytes: &[u8]) -> Result<Self> {
        match level {
            Dilithium::Dilithium2 => Ok(DilithiumPublicKey::Dilithium2(Box::new(dilithium2::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Dilithium::Dilithium3 => Ok(DilithiumPublicKey::Dilithium3(Box::new(dilithium3::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            Dilithium::Dilithium5 => Ok(DilithiumPublicKey::Dilithium5(Box::new(dilithium5::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumPublicKey::Dilithium2(_) => f.write_str("Dilithium2PublicKey"),
            DilithiumPublicKey::Dilithium3(_) => f.write_str("Dilithium3PublicKey"),
            DilithiumPublicKey::Dilithium5(_) => f.write_str("Dilithium5PublicKey"),
        }
    }
}

impl CBORTagged for DilithiumPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_DILITHIUM_PUBLIC_KEY])
    }
}

impl From<DilithiumPublicKey> for CBOR {
    fn from(value: DilithiumPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for DilithiumPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        vec![
            self.level().into(),
            CBOR::to_byte_string(self.as_bytes())
        ].into()
    }
}

impl TryFrom<CBOR> for DilithiumPublicKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for DilithiumPublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("DilithiumPublicKey must have two elements");
                }

                let level = Dilithium::try_from(elements[0].clone())?;
                let data = CBOR::try_into_byte_string(elements[1].clone())?;
                DilithiumPublicKey::from_bytes(level, &data)
            }
            _ => bail!("DilithiumPublicKey must be an array"),
        }
    }
}
