use anyhow::{bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;

use super::{KyberPrivateKey, KyberPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Kyber {
    Kyber512 = 512,
    Kyber768 = 768,
    Kyber1024 = 1024,
}

impl Kyber {
    pub const SHARED_SECRET_SIZE: usize = mlkem512::shared_secret_bytes();

    pub fn keypair(self) -> (KyberPrivateKey, KyberPublicKey) {
        match self {
            Kyber::Kyber512 => {
                let (pk, sk) = mlkem512::keypair();
                (
                    KyberPrivateKey::Kyber512(sk.into()),
                    KyberPublicKey::Kyber512(pk.into()),
                )
            }
            Kyber::Kyber768 => {
                let (pk, sk) = mlkem768::keypair();
                (
                    KyberPrivateKey::Kyber768(sk.into()),
                    KyberPublicKey::Kyber768(pk.into()),
                )
            }
            Kyber::Kyber1024 => {
                let (pk, sk) = mlkem1024::keypair();
                (
                    KyberPrivateKey::Kyber1024(sk.into()),
                    KyberPublicKey::Kyber1024(pk.into()),
                )
            }
        }
    }

    pub fn private_key_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => mlkem512::secret_key_bytes(),
            Kyber::Kyber768 => mlkem768::secret_key_bytes(),
            Kyber::Kyber1024 => mlkem1024::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => mlkem512::public_key_bytes(),
            Kyber::Kyber768 => mlkem768::public_key_bytes(),
            Kyber::Kyber1024 => mlkem1024::public_key_bytes(),
        }
    }

    pub fn shared_secret_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => mlkem512::shared_secret_bytes(),
            Kyber::Kyber768 => mlkem768::shared_secret_bytes(),
            Kyber::Kyber1024 => mlkem1024::shared_secret_bytes(),
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            Kyber::Kyber512 => mlkem512::ciphertext_bytes(),
            Kyber::Kyber768 => mlkem768::ciphertext_bytes(),
            Kyber::Kyber1024 => mlkem1024::ciphertext_bytes(),
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
