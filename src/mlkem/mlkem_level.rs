use anyhow::{bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mlkem::*;

use super::{MLKEMPrivateKey, MLKEMPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MLKEM {
    MLKEM512 = 512,
    MLKEM768 = 768,
    MLKEM1024 = 1024,
}

impl MLKEM {
    pub const SHARED_SECRET_SIZE: usize = mlkem512::shared_secret_bytes();

    pub fn keypair(self) -> (MLKEMPrivateKey, MLKEMPublicKey) {
        match self {
            MLKEM::MLKEM512 => {
                let (pk, sk) = mlkem512::keypair();
                (
                    MLKEMPrivateKey::MLKEM512(sk.into()),
                    MLKEMPublicKey::MLKEM512(pk.into()),
                )
            }
            MLKEM::MLKEM768 => {
                let (pk, sk) = mlkem768::keypair();
                (
                    MLKEMPrivateKey::MLKEM768(sk.into()),
                    MLKEMPublicKey::MLKEM768(pk.into()),
                )
            }
            MLKEM::MLKEM1024 => {
                let (pk, sk) = mlkem1024::keypair();
                (
                    MLKEMPrivateKey::MLKEM1024(sk.into()),
                    MLKEMPublicKey::MLKEM1024(pk.into()),
                )
            }
        }
    }

    pub fn private_key_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::secret_key_bytes(),
            MLKEM::MLKEM768 => mlkem768::secret_key_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::public_key_bytes(),
            MLKEM::MLKEM768 => mlkem768::public_key_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::public_key_bytes(),
        }
    }

    pub fn shared_secret_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::shared_secret_bytes(),
            MLKEM::MLKEM768 => mlkem768::shared_secret_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::shared_secret_bytes(),
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            MLKEM::MLKEM512 => mlkem512::ciphertext_bytes(),
            MLKEM::MLKEM768 => mlkem768::ciphertext_bytes(),
            MLKEM::MLKEM1024 => mlkem1024::ciphertext_bytes(),
        }
    }
}

impl From<MLKEM> for CBOR {
    fn from(mlkem: MLKEM) -> Self {
        (mlkem as u32).into()
    }
}

impl TryFrom<CBOR> for MLKEM {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let level = u32::try_from(cbor)?;
        match level {
            512 => Ok(MLKEM::MLKEM512),
            768 => Ok(MLKEM::MLKEM768),
            1024 => Ok(MLKEM::MLKEM1024),
            _ => bail!("Invalid MLKEM level: {}", level),
        }
    }
}
