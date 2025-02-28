use anyhow::{bail, Error, Result};
use dcbor::prelude::*;
use pqcrypto_mldsa::*;

use super::{MLDSAPrivateKey, MLDSAPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MLDSA {
    MLDSA44 = 2,
    MLDSA65 = 3,
    MLDSA87 = 5,
}

impl MLDSA {
    pub fn keypair(self) -> (MLDSAPrivateKey, MLDSAPublicKey) {
        match self {
            MLDSA::MLDSA44 => {
                let (pk, sk) = mldsa44::keypair();
                (
                    MLDSAPrivateKey::MLDSA44(Box::new(sk)),
                    MLDSAPublicKey::MLDSA44(Box::new(pk)),
                )
            }
            MLDSA::MLDSA65 => {
                let (pk, sk) = mldsa65::keypair();
                (
                    MLDSAPrivateKey::MLDSA65(Box::new(sk)),
                    MLDSAPublicKey::MLDSA65(Box::new(pk)),
                )
            }
            MLDSA::MLDSA87 => {
                let (pk, sk) = mldsa87::keypair();
                (
                    MLDSAPrivateKey::MLDSA87(Box::new(sk)),
                    MLDSAPublicKey::MLDSA87(Box::new(pk)),
                )
            }
        }
    }

    pub fn private_key_size(&self) -> usize {
        match self {
            MLDSA::MLDSA44 => mldsa44::secret_key_bytes(),
            MLDSA::MLDSA65 => mldsa65::secret_key_bytes(),
            MLDSA::MLDSA87 => mldsa87::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            MLDSA::MLDSA44 => mldsa44::public_key_bytes(),
            MLDSA::MLDSA65 => mldsa65::public_key_bytes(),
            MLDSA::MLDSA87 => mldsa87::public_key_bytes(),
        }
    }

    pub fn signature_size(&self) -> usize {
        match self {
            MLDSA::MLDSA44 => mldsa44::signature_bytes(),
            MLDSA::MLDSA65 => mldsa65::signature_bytes(),
            MLDSA::MLDSA87 => mldsa87::signature_bytes(),
        }
    }
}

impl From<MLDSA> for CBOR {
    fn from(level: MLDSA) -> Self {
        (level as u32).into()
    }
}

impl TryFrom<CBOR> for MLDSA {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let level = u32::try_from(cbor)?;
        match level {
            2 => Ok(MLDSA::MLDSA44),
            3 => Ok(MLDSA::MLDSA65),
            5 => Ok(MLDSA::MLDSA87),
            _ => bail!("Invalid MLDSA level: {}", level),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_level() {
        let level = MLDSA::MLDSA44;
        assert_eq!(format!("{:?}", level), "MLDSA44");
        let cbor = CBOR::from(level);
        let level2 = MLDSA::try_from(cbor).unwrap();
        assert_eq!(level, level2);

        let level = MLDSA::MLDSA65;
        assert_eq!(format!("{:?}", level), "MLDSA65");
        let cbor = CBOR::from(level);
        let level2 = MLDSA::try_from(cbor).unwrap();
        assert_eq!(level, level2);

        let level = MLDSA::MLDSA87;
        assert_eq!(format!("{:?}", level), "MLDSA87");
        let cbor = CBOR::from(level);
        let level2 = MLDSA::try_from(cbor).unwrap();
        assert_eq!(level, level2);
    }
}
