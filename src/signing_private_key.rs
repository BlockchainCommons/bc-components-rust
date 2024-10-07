use std::{ cell::RefCell, rc::Rc };

use bc_ur::prelude::*;
use crate::{ tags, ECKey, ECPrivateKey, Signature, Signer, SigningPublicKey, Verifier };
use bc_rand::{ RandomNumberGenerator, SecureRandomNumberGenerator };
use anyhow::{ bail, Result, Error };
use ssh_key::{ private::PrivateKey as SSHPrivateKey, HashAlg, LineEnding };

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
#[derive(Clone, PartialEq, Eq)]
pub enum SigningPrivateKey {
    Schnorr(ECPrivateKey),
    ECDSA(ECPrivateKey),
    SSH(Box<SSHPrivateKey>),
}

impl SigningPrivateKey {
    pub const fn new_schnorr(key: ECPrivateKey) -> Self {
        Self::Schnorr(key)
    }

    pub const fn new_ecdsa(key: ECPrivateKey) -> Self {
        Self::ECDSA(key)
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

    pub fn public_key(&self) -> SigningPublicKey {
        match self {
            Self::Schnorr(key) => { SigningPublicKey::from_schnorr(key.schnorr_public_key()) }
            Self::ECDSA(key) => { SigningPublicKey::from_ecdsa(key.public_key()) }
            Self::SSH(key) => { SigningPublicKey::from_ssh(key.public_key().clone()) }
        }
    }
}

impl SigningPrivateKey {
    fn ecdsa_sign(&self, message: impl AsRef<[u8]>) -> Result<Signature> {
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
            Self::ECDSA(_) => { self.ecdsa_sign(message) }
            Self::SSH(_) => {
                if let Some(SigningOptions::Ssh { namespace, hash_alg }) = options {
                    self.ssh_sign(message, namespace, hash_alg)
                } else {
                    bail!("Missing namespace and hash algorithm for SSH signing");
                }
            }
        }
    }
}

impl Verifier for SigningPrivateKey {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        let public_key = self.public_key();
        public_key.verify(signature, message)
    }
}

impl CBORTagged for SigningPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SIGNING_PRIVATE_KEY]
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
            SigningPrivateKey::SSH(key) => {
                let string = key.to_openssh(LineEnding::LF).unwrap();
                CBOR::to_tagged_value(tags::SSH_TEXT_PRIVATE_KEY, (*string).clone())
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
        // let data = CBOR::try_into_byte_string(untagged_cbor)?;
        // Self::from_data_ref(&data)
        match untagged_cbor.into_case() {
            CBORCase::ByteString(data) => { Ok(Self::Schnorr(ECPrivateKey::from_data_ref(data)?)) }
            CBORCase::Array(mut elements) => {
                let tag = usize::try_from(elements.remove(0))?;
                if tag == 1 {
                    let data = elements.remove(0).try_into_byte_string()?;
                    let key = ECPrivateKey::from_data_ref(data)?;
                    return Ok(Self::ECDSA(key));
                }
                bail!("Invalid tag for SigningPrivateKey");
            }
            CBORCase::Tagged(tag, item) => {
                if tag == tags::SSH_TEXT_PRIVATE_KEY {
                    let string = item.try_into_text()?;
                    let key = SSHPrivateKey::from_openssh(string)?;
                    return Ok(Self::SSH(Box::new(key)));
                }
                bail!("Invalid CBOR tag for SigningPrivateKey");
            }
            _ => bail!("Invalid CBOR case for SigningPrivateKey"),
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
