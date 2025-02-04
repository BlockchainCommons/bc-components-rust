use std::{ cell::RefCell, rc::Rc };

use bc_ur::prelude::*;
use crate::{ tags, DilithiumPrivateKey, ECKey, ECPrivateKey, Ed25519PrivateKey, Signature, Signer, SigningPublicKey };
use bc_rand::{ RandomNumberGenerator, SecureRandomNumberGenerator };
use anyhow::{ bail, Result, Error };
use ssh_key::{ private::PrivateKey as SSHPrivateKey, HashAlg, LineEnding };

use super::Verifier;

/// Options for signing a message.
///
/// - ECDSA signing requires no options.
/// - Schnorr signing may take `None` for options, or a tag and RNG.
/// - SSH signing requires a namespace and hash algorithm.
#[derive(Clone)]
pub enum SigningOptions {
    Schnorr {
        rng: Rc<RefCell<dyn RandomNumberGenerator>>,
    },
    Ssh {
        namespace: String,
        hash_alg: HashAlg,
    },
}

/// A private ECDSA, Schnorr or SSH key for signing.
///
/// - Both ECDSA and Schnorr keys are based on `ECPrivateKey`.
/// - SSH keys are based on `SSHPrivateKey`, an alias for (`ssh_key::PrivateKey`).
#[derive(Clone, PartialEq)]
pub enum SigningPrivateKey {
    Schnorr(ECPrivateKey),
    ECDSA(ECPrivateKey),
    Ed25519(Ed25519PrivateKey),
    SSH(Box<SSHPrivateKey>),
    Dilithium(DilithiumPrivateKey),
}

impl std::hash::Hash for SigningPrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Schnorr(key) => key.hash(state),
            Self::ECDSA(key) => key.hash(state),
            Self::Ed25519(key) => key.hash(state),
            Self::SSH(key) => key.to_bytes().unwrap().hash(state),
            Self::Dilithium(key) => key.as_bytes().hash(state),
        }
    }
}

impl Eq for SigningPrivateKey {}

impl SigningPrivateKey {
    pub const fn new_schnorr(key: ECPrivateKey) -> Self {
        Self::Schnorr(key)
    }

    pub const fn new_ecdsa(key: ECPrivateKey) -> Self {
        Self::ECDSA(key)
    }

    pub const fn new_ed25519(key: Ed25519PrivateKey) -> Self {
        Self::Ed25519(key)
    }

    pub fn new_ssh(key: SSHPrivateKey) -> Self {
        Self::SSH(Box::new(key))
    }

    pub fn to_schnorr(&self) -> Option<&ECPrivateKey> {
        match self {
            Self::Schnorr(key) => Some(key),
            _ => None,
        }
    }

    pub fn is_schnorr(&self) -> bool {
        self.to_schnorr().is_some()
    }

    pub fn to_ecdsa(&self) -> Option<&ECPrivateKey> {
        match self {
            Self::ECDSA(key) => Some(key),
            _ => None,
        }
    }

    pub fn is_ecdsa(&self) -> bool {
        self.to_ecdsa().is_some()
    }

    pub fn to_ssh(&self) -> Option<&SSHPrivateKey> {
        match self {
            Self::SSH(key) => Some(key),
            _ => None,
        }
    }

    pub fn is_ssh(&self) -> bool {
        self.to_ssh().is_some()
    }

    pub fn public_key(&self) -> Result<SigningPublicKey> {
        match self {
            Self::Schnorr(key)  => Ok(SigningPublicKey::from_schnorr(key.schnorr_public_key())),
            Self::ECDSA(key)    => Ok(SigningPublicKey::from_ecdsa(key.public_key())),
            Self::Ed25519(key)  => Ok(SigningPublicKey::from_ed25519(key.public_key())),
            Self::SSH(key)      => Ok(SigningPublicKey::from_ssh(key.public_key().clone())),
            Self::Dilithium(_)  => bail!("Deriving Dilithium public key not supported"),
        }
    }
}

impl SigningPrivateKey {
    fn ecdsa_sign(
        &self,
        message: impl AsRef<[u8]>
    ) -> Result<Signature> {
        if let Some(private_key) = self.to_ecdsa() {
            let sig = private_key.ecdsa_sign(message);
            Ok(Signature::ecdsa_from_data(sig))
        } else {
            bail!("Invalid key type for ECDSA signing");
        }
    }

    pub fn schnorr_sign(
        &self,
        message: impl AsRef<[u8]>,
        rng: Rc<RefCell<dyn RandomNumberGenerator>>
    ) -> Result<Signature> {
        if let Some(private_key) = self.to_schnorr() {
            let sig = private_key.schnorr_sign_using(message, &mut *rng.borrow_mut());
            Ok(Signature::schnorr_from_data(sig))
        } else {
            bail!("Invalid key type for Schnorr signing");
        }
    }

    pub fn ed25519_sign(
        &self,
        message: impl AsRef<[u8]>
    ) -> Result<Signature> {
        if let Self::Ed25519(key) = self {
            let sig = key.sign(message.as_ref());
            Ok(Signature::ed25519_from_data(sig))
        } else {
            bail!("Invalid key type for Ed25519 signing");
        }
    }

    fn ssh_sign(
        &self,
        message: impl AsRef<[u8]>,
        namespace: impl AsRef<str>,
        hash_alg: HashAlg
    ) -> Result<Signature> {
        if let Some(private) = self.to_ssh() {
            let sig = private.sign(namespace.as_ref(), hash_alg, message.as_ref())?;
            Ok(Signature::from_ssh(sig))
        } else {
            bail!("Invalid key type for SSH signing");
        }
    }

    fn dilithium_sign(
        &self,
        message: impl AsRef<[u8]>,
    ) -> Result<Signature> {
        if let Self::Dilithium(key) = self {
            let sig = key.sign(message.as_ref());
            Ok(Signature::Dilithium(sig))
        } else {
            bail!("Invalid key type for Dilithium signing");
        }
    }
}

impl Signer for SigningPrivateKey {
    fn sign_with_options(
        &self,
        message: &dyn AsRef<[u8]>,
        options: Option<SigningOptions>
    ) -> Result<Signature> {
        match self {
            Self::Schnorr(_) => {
                if let Some(SigningOptions::Schnorr { rng }) = options {
                    self.schnorr_sign(message, rng)
                } else {
                    self.schnorr_sign(
                        message,
                        Rc::new(RefCell::new(SecureRandomNumberGenerator))
                    )
                }
            }
            Self::ECDSA(_) => self.ecdsa_sign(message),
            Self::Ed25519(_) => self.ed25519_sign(message),
            Self::SSH(_) => {
                if let Some(SigningOptions::Ssh { namespace, hash_alg }) = options {
                    self.ssh_sign(message, namespace, hash_alg)
                } else {
                    bail!("Missing namespace and hash algorithm for SSH signing");
                }
            }
            Self::Dilithium(_) => {
                self.dilithium_sign(message)
            }
        }
    }
}

impl Verifier for SigningPrivateKey {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        match self {
            Self::Schnorr(key) => {
                if let Signature::Schnorr(sig) = signature {
                    key.schnorr_public_key().schnorr_verify(sig, message)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

impl CBORTagged for SigningPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SIGNING_PRIVATE_KEY])
    }
}

impl From<SigningPrivateKey> for CBOR {
    fn from(value: SigningPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SigningPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            SigningPrivateKey::Schnorr(key) => { CBOR::to_byte_string(key.data()) }
            SigningPrivateKey::ECDSA(key) => {
                vec![(1).into(), CBOR::to_byte_string(key.data())].into()
            }
            SigningPrivateKey::Ed25519(key) => {
                vec![(2).into(), CBOR::to_byte_string(key.data())].into()
            }
            SigningPrivateKey::SSH(key) => {
                let string = key.to_openssh(LineEnding::LF).unwrap();
                CBOR::to_tagged_value(tags::TAG_SSH_TEXT_PRIVATE_KEY, (*string).clone())
            }
            SigningPrivateKey::Dilithium(key) => {
                key.clone().into()
            }
        }
    }
}

impl TryFrom<CBOR> for SigningPrivateKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SigningPrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.into_case() {
            CBORCase::ByteString(data) => {
                Ok(Self::Schnorr(ECPrivateKey::from_data_ref(data)?))
            }
            CBORCase::Array(mut elements) => {
                let discriminator = usize::try_from(elements.remove(0))?;
                match discriminator {
                    1 => {
                        let data = elements.remove(0).try_into_byte_string()?;
                        let key = ECPrivateKey::from_data_ref(data)?;
                        Ok(Self::ECDSA(key))
                    },
                    2 => {
                        let data = elements.remove(0).try_into_byte_string()?;
                        let key = Ed25519PrivateKey::from_data_ref(data)?;
                        Ok(Self::Ed25519(key))
                    },
                    _ => bail!("Invalid discriminator for SigningPrivateKey: {}", discriminator)
                }
            }
            CBORCase::Tagged(tag, item) => {
                let value = tag.value();
                match value {
                    tags::TAG_SSH_TEXT_PRIVATE_KEY => {
                        let string = item.try_into_text()?;
                        let key = SSHPrivateKey::from_openssh(string)?;
                        Ok(Self::SSH(Box::new(key)))
                    }
                    tags::TAG_DILITHIUM_PRIVATE_KEY => {
                        let key = DilithiumPrivateKey::from_untagged_cbor(item)?;
                        Ok(Self::Dilithium(key))
                    }
                    _ => bail!("Invalid CBOR tag for SigningPrivateKey: {}", value),
                }
            }
            _ => {
                bail!("Invalid CBOR case for SigningPrivateKey");
            }
        }
    }
}

impl std::fmt::Debug for SigningPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningPrivateKey")
    }
}

// Convert from a reference to a byte vector to a SigningPrivateKey.
impl From<&SigningPrivateKey> for SigningPrivateKey {
    fn from(key: &SigningPrivateKey) -> Self {
        key.clone()
    }
}
