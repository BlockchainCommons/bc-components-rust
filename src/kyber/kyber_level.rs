use anyhow::{Result, Error, bail};
use dcbor::prelude::*;
use pqcrypto_kyber::*;

use super::{KyberPrivateKey, KyberPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Kyber {
    Kyber512 = 512,
    Kyber768 = 768,
    Kyber1024 = 1024,
}

impl Kyber {
    pub const SHARED_SECRET_SIZE: usize = kyber512::shared_secret_bytes();

    pub fn keypair(self) -> (KyberPrivateKey, KyberPublicKey) {
        match self {
            Kyber::Kyber512 => {
                let (pk, sk) = kyber512::keypair();
                (KyberPrivateKey::Kyber512(sk.into()), KyberPublicKey::Kyber512(pk.into()))
            }
            Kyber::Kyber768 => {
                let (pk, sk) = kyber768::keypair();
                (KyberPrivateKey::Kyber768(sk.into()), KyberPublicKey::Kyber768(pk.into()))
            }
            Kyber::Kyber1024 => {
                let (pk, sk) = kyber1024::keypair();
                (KyberPrivateKey::Kyber1024(sk.into()), KyberPublicKey::Kyber1024(pk.into()))
            }
        }
    }

    pub fn private_key_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => kyber512::secret_key_bytes(),
            Kyber::Kyber768 => kyber768::secret_key_bytes(),
            Kyber::Kyber1024 => kyber1024::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => kyber512::public_key_bytes(),
            Kyber::Kyber768 => kyber768::public_key_bytes(),
            Kyber::Kyber1024 => kyber1024::public_key_bytes(),
        }
    }

    pub fn shared_secret_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => kyber512::shared_secret_bytes(),
            Kyber::Kyber768 => kyber768::shared_secret_bytes(),
            Kyber::Kyber1024 => kyber1024::shared_secret_bytes(),
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => kyber512::ciphertext_bytes(),
            Kyber::Kyber768 => kyber768::ciphertext_bytes(),
            Kyber::Kyber1024 => kyber1024::ciphertext_bytes(),
        }
    }
}

impl From<Kyber> for CBOR {
    fn from(kyber: Kyber) -> Self {
        (kyber as u32).into()
    }
}

impl TryFrom<CBOR> for Kyber {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let level = u32::try_from(cbor)?;
        match level {
            512 => Ok(Kyber::Kyber512),
            768 => Ok(Kyber::Kyber768),
            1024 => Ok(Kyber::Kyber1024),
            _ => bail!("Invalid Kyber level: {}", level),
        }
    }
}
