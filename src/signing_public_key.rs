use crate::{SchnorrPublicKey, ECPublicKey, tags, ECKeyBase, Signature};
use anyhow::bail;
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
    pub fn verify<D>(&self, signature: &Signature, message: D) -> bool
    where
        D: AsRef<[u8]>,
    {
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
    const CBOR_TAG: Tag = tags::SIGNING_PUBLIC_KEY;
}

impl CBOREncodable for SigningPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SigningPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            SigningPublicKey::Schnorr(key) => {
                CBOR::byte_string(key.data())
            },
            SigningPublicKey::ECDSA(key) => {
                vec![
                    1.cbor(),
                    CBOR::byte_string(key.data()),
                ].cbor()
            },
        }
    }
}

impl UREncodable for SigningPublicKey { }

impl CBORDecodable for SigningPublicKey {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SigningPublicKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> anyhow::Result<Self> {
        match untagged_cbor {
            CBOR::ByteString(data) => {
                Ok(Self::Schnorr(SchnorrPublicKey::from_data_ref(data)?))
            },
            CBOR::Array(elements) => {
                if elements.len() == 2 {
                    if let CBOR::Unsigned(1) = &elements[0] {
                        if let Some(data) = CBOR::as_byte_string(&elements[1]) {
                            return Ok(Self::ECDSA(ECPublicKey::from_data_ref(&data)?));
                        }
                    }
                }
                bail!("invalid ECDSA public key");
            },
            _ => bail!("invalid ECDSA public key"),
        }
    }
}

impl URDecodable for SigningPublicKey { }

impl URCodable for SigningPublicKey { }
