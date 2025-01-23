use anyhow::{Result, Error, bail};
use dcbor::prelude::*;
use pqcrypto_dilithium::*;

use super::{DilithiumPrivateKey, DilithiumPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Dilithium {
    Dilithium2 = 2,
    Dilithium3 = 3,
    Dilithium5 = 5,
}

impl Dilithium {
    pub fn keypair(self) -> (DilithiumPublicKey, DilithiumPrivateKey) {
        match self {
            Dilithium::Dilithium2 => {
                let (pk, sk) = dilithium2::keypair();
                (DilithiumPublicKey::Dilithium2(Box::new(pk)), DilithiumPrivateKey::Dilithium2(Box::new(sk)))
            },
            Dilithium::Dilithium3 => {
                let (pk, sk) = dilithium3::keypair();
                (DilithiumPublicKey::Dilithium3(Box::new(pk)), DilithiumPrivateKey::Dilithium3(Box::new(sk)))
            },
            Dilithium::Dilithium5 => {
                let (pk, sk) = dilithium5::keypair();
                (DilithiumPublicKey::Dilithium5(Box::new(pk)), DilithiumPrivateKey::Dilithium5(Box::new(sk)))
            },
        }
    }

    pub fn private_key_size(&self) -> usize {
        match self {
            Dilithium::Dilithium2 => dilithium2::secret_key_bytes(),
            Dilithium::Dilithium3 => dilithium3::secret_key_bytes(),
            Dilithium::Dilithium5 => dilithium5::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            Dilithium::Dilithium2 => dilithium2::public_key_bytes(),
            Dilithium::Dilithium3 => dilithium3::public_key_bytes(),
            Dilithium::Dilithium5 => dilithium5::public_key_bytes(),
        }
    }

    pub fn signature_size(&self) -> usize {
        match self {
            Dilithium::Dilithium2 => dilithium2::signature_bytes(),
            Dilithium::Dilithium3 => dilithium3::signature_bytes(),
            Dilithium::Dilithium5 => dilithium5::signature_bytes(),
        }
    }
}

impl From<Dilithium> for CBOR {
    fn from(level: Dilithium) -> Self {
        (level as u32).into()
    }
}

impl TryFrom<CBOR> for Dilithium {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let level = u32::try_from(cbor)?;
        match level {
            2 => Ok(Dilithium::Dilithium2),
            3 => Ok(Dilithium::Dilithium3),
            5 => Ok(Dilithium::Dilithium5),
            _ => bail!("Invalid Dilithium level: {}", level),
        }
    }
}
