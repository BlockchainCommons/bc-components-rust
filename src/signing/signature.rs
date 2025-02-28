use crate::{tags, MLDSASignature};
use anyhow::{bail, Error, Result};
use bc_crypto::{ECDSA_SIGNATURE_SIZE, ED25519_SIGNATURE_SIZE, SCHNORR_SIGNATURE_SIZE};
use bc_ur::prelude::*;
use ssh_key::{LineEnding, SshSig};

use super::SignatureScheme;

/// A cryptographic signature. Supports ECDSA and Schnorr.
#[derive(Clone)]
pub enum Signature {
    Schnorr([u8; SCHNORR_SIGNATURE_SIZE]),
    ECDSA([u8; ECDSA_SIGNATURE_SIZE]),
    Ed25519([u8; ED25519_SIGNATURE_SIZE]),
    SSH(SshSig),
    MLDSA(MLDSASignature),
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Schnorr(a), Self::Schnorr(b)) => a == b,
            (Self::ECDSA(a), Self::ECDSA(b)) => a == b,
            (Self::Ed25519(a), Self::Ed25519(b)) => a == b,
            (Self::SSH(a), Self::SSH(b)) => a == b,
            (Self::MLDSA(a), Self::MLDSA(b)) => a.as_bytes() == b.as_bytes(),
            _ => false,
        }
    }
}

impl Signature {
    /// Restores a Schnorr signature from an array of bytes.
    pub fn schnorr_from_data(data: [u8; SCHNORR_SIGNATURE_SIZE]) -> Self {
        Self::Schnorr(data)
    }

    /// Restores a Schnorr signature from an array of bytes.
    pub fn schnorr_from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != SCHNORR_SIGNATURE_SIZE {
            bail!("Invalid Schnorr signature size");
        }
        let mut arr = [0u8; SCHNORR_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::schnorr_from_data(arr))
    }

    /// Restores an ECDSA signature from an array of bytes.
    pub fn ecdsa_from_data(data: [u8; ECDSA_SIGNATURE_SIZE]) -> Self {
        Self::ECDSA(data)
    }

    /// Restores an ECDSA signature from an array of bytes.
    pub fn ecdsa_from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ECDSA_SIGNATURE_SIZE {
            bail!("Invalid ECDSA signature size");
        }
        let mut arr = [0u8; ECDSA_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::ecdsa_from_data(arr))
    }

    pub fn ed25519_from_data(data: [u8; ED25519_SIGNATURE_SIZE]) -> Self {
        Self::Ed25519(data)
    }

    pub fn ed25519_from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ED25519_SIGNATURE_SIZE {
            bail!("Invalid Ed25519 signature size");
        }
        let mut arr = [0u8; ED25519_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::Ed25519(arr))
    }

    /// Restores an SSH signature from a `SshSig`.
    pub fn from_ssh(sig: SshSig) -> Self {
        Self::SSH(sig)
    }

    pub fn to_schnorr(&self) -> Option<&[u8; SCHNORR_SIGNATURE_SIZE]> {
        match self {
            Self::Schnorr(sig) => Some(sig),
            _ => None,
        }
    }

    pub fn to_ecdsa(&self) -> Option<&[u8; ECDSA_SIGNATURE_SIZE]> {
        match self {
            Self::ECDSA(sig) => Some(sig),
            _ => None,
        }
    }

    pub fn to_ssh(&self) -> Option<&SshSig> {
        match self {
            Self::SSH(sig) => Some(sig),
            _ => None,
        }
    }

    pub fn scheme(&self) -> Result<SignatureScheme> {
        match self {
            Self::Schnorr(_) => Ok(SignatureScheme::Schnorr),
            Self::ECDSA(_) => Ok(SignatureScheme::Ecdsa),
            Self::Ed25519(_) => Ok(SignatureScheme::Ed25519),
            Self::SSH(sig) => match sig.algorithm() {
                ssh_key::Algorithm::Dsa => Ok(SignatureScheme::SshDsa),
                ssh_key::Algorithm::Ecdsa { curve } => match curve {
                    ssh_key::EcdsaCurve::NistP256 => Ok(SignatureScheme::SshEcdsaP256),
                    ssh_key::EcdsaCurve::NistP384 => Ok(SignatureScheme::SshEcdsaP384),
                    _ => bail!("Unsupported SSH ECDSA curve"),
                },
                ssh_key::Algorithm::Ed25519 => Ok(SignatureScheme::SshEd25519),
                _ => bail!("Unsupported SSH signature algorithm"),
            },
            Self::MLDSA(sig) => match sig.level() {
                crate::MLDSA::MLDSA44 => Ok(SignatureScheme::MLDSA44),
                crate::MLDSA::MLDSA65 => Ok(SignatureScheme::MLDSA65),
                crate::MLDSA::MLDSA87 => Ok(SignatureScheme::MLDSA87),
            },
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signature::Schnorr(data) => f
                .debug_struct("Schnorr")
                .field("data", &hex::encode(data))
                .finish(),
            Signature::ECDSA(data) => f
                .debug_struct("ECDSA")
                .field("data", &hex::encode(data))
                .finish(),
            Signature::Ed25519(data) => f
                .debug_struct("Ed25519")
                .field("data", &hex::encode(data))
                .finish(),
            Signature::SSH(sig) => f.debug_struct("SSH").field("sig", sig).finish(),
            Signature::MLDSA(sig) => f.debug_struct("MLDSA").field("sig", sig).finish(),
        }
    }
}

impl AsRef<Signature> for Signature {
    fn as_ref(&self) -> &Signature {
        self
    }
}

impl CBORTagged for Signature {
    fn cbor_tags() -> Vec<dcbor::Tag> {
        tags_for_values(&[tags::TAG_SIGNATURE])
    }
}

impl From<Signature> for CBOR {
    fn from(value: Signature) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Signature {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            Signature::Schnorr(data) => CBOR::to_byte_string(data),
            Signature::ECDSA(data) => vec![(1).into(), CBOR::to_byte_string(data)].into(),
            Signature::Ed25519(data) => vec![(2).into(), CBOR::to_byte_string(data)].into(),
            Signature::SSH(sig) => {
                let pem = sig.to_pem(LineEnding::LF).unwrap();
                CBOR::to_tagged_value(tags::TAG_SSH_TEXT_SIGNATURE, pem)
            }
            Signature::MLDSA(sig) => sig.clone().into(),
        }
    }
}

impl TryFrom<CBOR> for Signature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Signature {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        match cbor.clone().into_case() {
            CBORCase::ByteString(bytes) => Self::schnorr_from_data_ref(bytes),
            CBORCase::Array(mut elements) => {
                if elements.len() == 2 {
                    let mut drain = elements.drain(0..);
                    let ele_0 = drain.next().unwrap().into_case();
                    let ele_1 = drain.next().unwrap().into_case();
                    match ele_0 {
                        CBORCase::ByteString(data) => {
                            return Self::schnorr_from_data_ref(data);
                        }
                        CBORCase::Unsigned(1) => {
                            if let CBORCase::ByteString(data) = ele_1 {
                                return Self::ecdsa_from_data_ref(data);
                            }
                        }
                        CBORCase::Unsigned(2) => {
                            if let CBORCase::ByteString(data) = ele_1 {
                                return Self::ed25519_from_data_ref(data);
                            }
                        }
                        _ => (),
                    }
                }
                bail!("Invalid signature format");
            }
            CBORCase::Tagged(tag, item) => match tag.value() {
                tags::TAG_MLDSA_SIGNATURE => {
                    let sig = MLDSASignature::try_from(cbor)?;
                    Ok(Self::MLDSA(sig))
                }
                tags::TAG_SSH_TEXT_SIGNATURE => {
                    let string = item.try_into_text()?;
                    let pem = SshSig::from_pem(string)?;
                    Ok(Self::SSH(pem))
                }
                _ => bail!("Invalid signature format"),
            },
            _ => bail!("Invalid signature format"),
        }
    }
}
