use crate::{SchnorrPublicKey, ECPublicKey, tags, ECKeyBase, Signature};
use anyhow::{bail, Result, Error};
use bc_ur::prelude::*;

/// A public key that can be used for signing. Supports both ECDSA and Schnorr.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SigningPublicKey {
    Schnorr(SchnorrPublicKey),
    ECDSA(ECPublicKey),
}

impl SigningPublicKey {
    /// Restores a `SigningPublicKey` from a `SchnorrPublicKey`.
    pub fn from_schnorr(key: SchnorrPublicKey) -> Self {
        Self::Schnorr(key)
    }

    /// Restores a `SigningPublicKey` from an `ECPublicKey`.
    pub fn from_ecdsa(key: ECPublicKey) -> Self {
        Self::ECDSA(key)
    }

    /// Returns the `SchnorrPublicKey` of this `SigningPublicKey`, if it is a Schnorr key.
    pub fn schnorr(&self) -> Option<&SchnorrPublicKey> {
        match self {
            Self::Schnorr(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the `ECPublicKey` of this `SigningPublicKey`, if it is an ECDSA key.
    pub fn ecdsa(&self) -> Option<&ECPublicKey> {
        match self {
            Self::ECDSA(key) => Some(key),
            _ => None,
        }
    }

    /// Verifies a signature against a message.
    ///
    /// The type of signature must match the type of this key, and the
    /// signature must be valid for the message, or the verification
    /// will fail.
    pub fn verify(&self, signature: &Signature, message: impl AsRef<[u8]>) -> bool {
        match self {
            SigningPublicKey::Schnorr(key) => {
                match signature {
                    Signature::Schnorr { sig, tag } => key.schnorr_verify(sig, message, tag),
                    Signature::ECDSA(_) => false,
                }
            },
            SigningPublicKey::ECDSA(key) => {
                match signature {
                    Signature::Schnorr { .. } => false,
                    Signature::ECDSA(sig) => key.verify(sig, message),
                }
            },
        }
    }
}

impl AsRef<SigningPublicKey> for SigningPublicKey {
    fn as_ref(&self) -> &SigningPublicKey {
        self
    }
}

impl CBORTagged for SigningPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SIGNING_PUBLIC_KEY]
    }
}

impl From<SigningPublicKey> for CBOR {
    fn from(value: SigningPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SigningPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            SigningPublicKey::Schnorr(key) => {
                CBOR::to_byte_string(key.data())
            },
            SigningPublicKey::ECDSA(key) => {
                vec![
                    1.into(),
                    CBOR::to_byte_string(key.data()),
                ].into()
            },
        }
    }
}

impl TryFrom<CBOR> for SigningPublicKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SigningPublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.into_case() {
            CBORCase::ByteString(data) => {
                Ok(Self::Schnorr(SchnorrPublicKey::from_data_ref(data)?))
            },
            CBORCase::Array(mut elements) => {
                if elements.len() == 2 {
                    let mut drain = elements.drain(0..);
                    let ele_0 = drain.next().unwrap().into_case();
                    let ele_1 = drain.next().unwrap().into_case();
                    if let CBORCase::Unsigned(1) = ele_0 {
                        if let CBORCase::ByteString(data) = ele_1 {
                            return Ok(Self::ECDSA(ECPublicKey::from_data_ref(data)?));
                        }
                    }
                }
                bail!("invalid ECDSA public key");
            },
            _ => bail!("invalid ECDSA public key"),
        }
    }
}
