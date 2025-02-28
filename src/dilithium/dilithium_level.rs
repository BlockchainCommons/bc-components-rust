use anyhow::{bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;

use super::{DilithiumPrivateKey, DilithiumPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Dilithium {
    Dilithium2 = 2,
    Dilithium3 = 3,
    Dilithium5 = 5,
}

impl Dilithium {
    pub fn keypair(self) -> (DilithiumPrivateKey, DilithiumPublicKey) {
        match self {
            Dilithium::Dilithium2 => {
                let (pk, sk) = mldsa44::keypair();
                (
                    DilithiumPrivateKey::Dilithium2(Box::new(sk)),
                    DilithiumPublicKey::Dilithium2(Box::new(pk)),
                )
            }
            Dilithium::Dilithium3 => {
                let (pk, sk) = mldsa65::keypair();
                (
                    DilithiumPrivateKey::Dilithium3(Box::new(sk)),
                    DilithiumPublicKey::Dilithium3(Box::new(pk)),
                )
            }
            Dilithium::Dilithium5 => {
                let (pk, sk) = mldsa87::keypair();
                (
                    DilithiumPrivateKey::Dilithium5(Box::new(sk)),
                    DilithiumPublicKey::Dilithium5(Box::new(pk)),
                )
            }
        }
    }

    pub fn private_key_size(&self) -> usize {
        match self {
            Dilithium::Dilithium2 => mldsa44::secret_key_bytes(),
            Dilithium::Dilithium3 => mldsa65::secret_key_bytes(),
            Dilithium::Dilithium5 => mldsa87::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            Dilithium::Dilithium2 => mldsa44::public_key_bytes(),
            Dilithium::Dilithium3 => mldsa65::public_key_bytes(),
            Dilithium::Dilithium5 => mldsa87::public_key_bytes(),
        }
    }

    pub fn signature_size(&self) -> usize {
        match self {
            Dilithium::Dilithium2 => mldsa44::signature_bytes(),
            Dilithium::Dilithium3 => mldsa65::signature_bytes(),
            Dilithium::Dilithium5 => mldsa87::signature_bytes(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_level() {
        let level = Dilithium::Dilithium2;
        assert_eq!(format!("{:?}", level), "Dilithium2");
        let cbor = CBOR::from(level);
        let level2 = Dilithium::try_from(cbor).unwrap();
        assert_eq!(level, level2);

        let level = Dilithium::Dilithium3;
        assert_eq!(format!("{:?}", level), "Dilithium3");
        let cbor = CBOR::from(level);
        let level2 = Dilithium::try_from(cbor).unwrap();
        assert_eq!(level, level2);

        let level = Dilithium::Dilithium5;
        assert_eq!(format!("{:?}", level), "Dilithium5");
        let cbor = CBOR::from(level);
        let level2 = Dilithium::try_from(cbor).unwrap();
        assert_eq!(level, level2);
    }
}
