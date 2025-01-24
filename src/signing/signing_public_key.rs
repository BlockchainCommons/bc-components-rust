use crate::{ tags, DilithiumPublicKey, ECKeyBase, ECPublicKey, Ed25519PublicKey, SchnorrPublicKey, Signature, Verifier };
use anyhow::{ bail, Result, Error };
use bc_ur::prelude::*;
use ssh_key::public::PublicKey as SSHPublicKey;

/// A public key that can be used for signing. Supports both ECDSA and Schnorr.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SigningPublicKey {
    Schnorr(SchnorrPublicKey),
    ECDSA(ECPublicKey),
    Ed25519(Ed25519PublicKey),
    SSH(SSHPublicKey),
    Dilithium(DilithiumPublicKey),
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

    /// Restores a `SigningPublicKey` from an `Ed25519PublicKey`.
    pub fn from_ed25519(key: Ed25519PublicKey) -> Self {
        Self::Ed25519(key)
    }

    /// Restores a `SigningPublicKey` from an SSH public key.
    pub fn from_ssh(key: SSHPublicKey) -> Self {
        Self::SSH(key)
    }

    /// Returns the `SchnorrPublicKey` of this `SigningPublicKey`, if it is a Schnorr key.
    pub fn to_schnorr(&self) -> Option<&SchnorrPublicKey> {
        match self {
            Self::Schnorr(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the `ECPublicKey` of this `SigningPublicKey`, if it is an ECDSA key.
    pub fn to_ecdsa(&self) -> Option<&ECPublicKey> {
        match self {
            Self::ECDSA(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the SSH public key of this `SigningPublicKey`, if it is an SSH key.
    pub fn to_ssh(&self) -> Option<&SSHPublicKey> {
        match self {
            Self::SSH(key) => Some(key),
            _ => None,
        }
    }
}

impl Verifier for SigningPublicKey {
    /// Verifies a signature against a message.
    ///
    /// The type of signature must match the type of this key, and the
    /// signature must be valid for the message, or the verification
    /// will fail.
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        match self {
            SigningPublicKey::Schnorr(key) => {
                match signature {
                    Signature::Schnorr(sig) => key.schnorr_verify::<_, &[u8]>(sig, message),
                    _ => false,
                }
            }
            SigningPublicKey::ECDSA(key) => {
                match signature {
                    Signature::ECDSA(sig) => key.verify(sig, message),
                    _ => false,
                }
            }
            SigningPublicKey::Ed25519(key) => {
                match signature {
                    Signature::Ed25519(sig) => key.verify(sig, message),
                    _ => false,
                }
            }
            SigningPublicKey::SSH(key) => {
                match signature {
                    Signature::SSH(sig) =>
                        key.verify(sig.namespace(), message.as_ref(), sig).is_ok(),
                    _ => false,
                }
            }
            SigningPublicKey::Dilithium(key) => {
                match signature {
                    Signature::Dilithium(sig) => key.verify(sig, message).map_err(|_| false).unwrap_or(false),
                    _ => false,
                }
            }
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
        tags_for_values(&[tags::TAG_SIGNING_PUBLIC_KEY])
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
            SigningPublicKey::Schnorr(key) => { CBOR::to_byte_string(key.data()) }
            SigningPublicKey::ECDSA(key) => {
                vec![(1).into(), CBOR::to_byte_string(key.data())].into()
            }
            SigningPublicKey::Ed25519(key) => {
                vec![(2).into(), CBOR::to_byte_string(key.data())].into()
            }
            SigningPublicKey::SSH(key) => {
                let string = key.to_openssh().unwrap();
                CBOR::to_tagged_value(tags::TAG_SSH_TEXT_PUBLIC_KEY, string)
            }
            SigningPublicKey::Dilithium(key) => {
                key.clone().into()
            }
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
        match untagged_cbor.clone().into_case() {
            CBORCase::ByteString(data) => {
                Ok(Self::Schnorr(SchnorrPublicKey::from_data_ref(data)?))
            }
            CBORCase::Array(mut elements) => {
                if elements.len() == 2 {
                    let mut drain = elements.drain(0..);
                    let ele_0 = drain.next().unwrap().into_case();
                    let ele_1 = drain.next().unwrap().into_case();
                    if let CBORCase::Unsigned(1) = ele_0 {
                        if let CBORCase::ByteString(data) = ele_1 {
                            return Ok(Self::ECDSA(ECPublicKey::from_data_ref(data)?));
                        }
                    } else if let CBORCase::Unsigned(2) = ele_0 {
                        if let CBORCase::ByteString(data) = ele_1 {
                            return Ok(Self::Ed25519(Ed25519PublicKey::from_data_ref(data)?));
                        }
                    }
                }
                bail!("invalid signing public key");
            }
            CBORCase::Tagged(tag, item) => {
                match tag.value() {
                    tags::TAG_SSH_TEXT_PUBLIC_KEY => {
                        let string = item.try_into_text()?;
                        let key = SSHPublicKey::from_openssh(&string)?;
                        Ok(Self::SSH(key))
                    }
                    tags::TAG_DILITHIUM_PUBLIC_KEY => {
                        let key = DilithiumPublicKey::from_tagged_cbor(untagged_cbor)?;
                        Ok(Self::Dilithium(key))
                    }
                    _ => bail!("invalid signing public key"),
                }
            }
            _ => bail!("invalid signing public key"),
        }
    }
}
