use std::{cell::RefCell, rc::Rc};

use bc_rand::RandomNumberGenerator;
#[cfg(feature = "secp256k1")]
use bc_rand::SecureRandomNumberGenerator;
use bc_ur::prelude::*;
#[cfg(feature = "ssh")]
use ssh_key::{HashAlg, LineEnding, private::PrivateKey as SSHPrivateKey};

use super::Verifier;
#[cfg(feature = "ed25519")]
use crate::Ed25519PrivateKey;
#[cfg(any(feature = "secp256k1", feature = "ssh", feature = "pqcrypto"))]
use crate::Error;
#[cfg(feature = "pqcrypto")]
use crate::MLDSAPrivateKey;
use crate::{
    Digest, Reference, ReferenceProvider, Result, Signature, Signer,
    SigningPublicKey, tags,
};
#[cfg(feature = "secp256k1")]
use crate::{ECKey, ECPrivateKey};

/// Options for configuring signature creation.
///
/// Different signature schemes may require specific options:
///
/// - `Schnorr`: Requires a random number generator for signature creation
/// - `Ssh`: Requires a namespace and hash algorithm
///
/// Other signature types like ECDSA, Ed25519, and ML-DSA don't require options.
///
/// # Examples
///
/// Creating Schnorr signing options:
///
/// ```
/// use std::{cell::RefCell, rc::Rc};
///
/// use bc_components::SigningOptions;
/// use bc_rand::SecureRandomNumberGenerator;
///
/// let rng = Rc::new(RefCell::new(SecureRandomNumberGenerator));
/// let options = SigningOptions::Schnorr { rng };
/// ```
///
/// Creating SSH signing options:
///
/// ```ignore
/// use bc_components::SigningOptions;
/// use ssh_key::HashAlg;
///
/// let options = SigningOptions::Ssh {
///     namespace: "ssh".to_string(),
///     hash_alg: HashAlg::Sha512,
/// };
/// ```
#[derive(Clone)]
pub enum SigningOptions {
    /// Options for Schnorr signatures
    Schnorr {
        /// Non-default random number generator used for signature creation
        rng: Rc<RefCell<dyn RandomNumberGenerator>>,
    },

    /// Options for SSH signatures
    #[cfg(feature = "ssh")]
    Ssh {
        /// The namespace used for SSH signatures
        namespace: String,

        /// The hash algorithm used for SSH signatures
        hash_alg: HashAlg,
    },
}

/// A private key used for creating digital signatures.
///
/// `SigningPrivateKey` is an enum representing different types of signing
/// private keys, including elliptic curve schemes (ECDSA, Schnorr), Edwards
/// curve schemes (Ed25519), post-quantum schemes (ML-DSA), and SSH keys.
///
/// This type implements the `Signer` trait, allowing it to create signatures of
/// the appropriate type.
///
/// # Examples
///
/// Creating a new Schnorr signing key and using it to sign a message:
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{ECPrivateKey, Signer, SigningPrivateKey, Verifier};
///
/// // Create a new Schnorr signing key
/// let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
///
/// // Get the corresponding public key
/// let public_key = private_key.public_key().unwrap();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.sign(&message).unwrap();
///
/// // Verify the signature
/// assert!(public_key.verify(&signature, &message));
/// ```
///
/// # CBOR Serialization
///
/// `SigningPrivateKey` can be serialized to and from CBOR with appropriate
/// tags:
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{ECPrivateKey, SigningPrivateKey};
/// use dcbor::prelude::*;
///
/// // Create a key
/// let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
///
/// // Convert to CBOR
/// let cbor: CBOR = private_key.clone().into();
/// let data = cbor.to_cbor_data();
///
/// // Convert back from CBOR
/// let recovered = SigningPrivateKey::from_tagged_cbor_data(&data).unwrap();
///
/// // The keys should be equal
/// assert_eq!(private_key, recovered);
/// ```
#[derive(Clone, PartialEq)]
pub enum SigningPrivateKey {
    /// A Schnorr private key based on the secp256k1 curve
    #[cfg(feature = "secp256k1")]
    Schnorr(ECPrivateKey),

    /// An ECDSA private key based on the secp256k1 curve
    #[cfg(feature = "secp256k1")]
    ECDSA(ECPrivateKey),

    /// An Ed25519 private key
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519PrivateKey),

    /// An SSH private key
    #[cfg(feature = "ssh")]
    SSH(Box<SSHPrivateKey>),

    /// A post-quantum ML-DSA private key
    #[cfg(feature = "pqcrypto")]
    MLDSA(MLDSAPrivateKey),
}

/// Implementation of hashing for SigningPrivateKey
impl std::hash::Hash for SigningPrivateKey {
    /// Hashes the key's data.
    ///
    /// This is used for collections that require hash support.
    #[allow(unreachable_patterns)]
    fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr(key) => key.hash(_state),
            #[cfg(feature = "secp256k1")]
            Self::ECDSA(key) => key.hash(_state),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => key.hash(_state),
            #[cfg(feature = "ssh")]
            Self::SSH(key) => key.to_bytes().unwrap().hash(_state),
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA(key) => key.as_bytes().hash(_state),
            #[cfg(not(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "ssh",
                feature = "pqcrypto"
            )))]
            _ => unreachable!(),
        }
    }
}

impl Eq for SigningPrivateKey {}

impl SigningPrivateKey {
    /// Creates a new Schnorr signing private key from an `ECPrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The elliptic curve private key to use
    ///
    /// # Returns
    ///
    /// A new Schnorr signing private key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{ECPrivateKey, SigningPrivateKey};
    ///
    /// // Create a new EC private key
    /// let ec_key = ECPrivateKey::new();
    ///
    /// // Create a Schnorr signing key from it
    /// let signing_key = SigningPrivateKey::new_schnorr(ec_key);
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub const fn new_schnorr(key: ECPrivateKey) -> Self {
        Self::Schnorr(key)
    }

    /// Creates a new ECDSA signing private key from an `ECPrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The elliptic curve private key to use
    ///
    /// # Returns
    ///
    /// A new ECDSA signing private key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{ECPrivateKey, SigningPrivateKey};
    ///
    /// // Create a new EC private key
    /// let ec_key = ECPrivateKey::new();
    ///
    /// // Create an ECDSA signing key from it
    /// let signing_key = SigningPrivateKey::new_ecdsa(ec_key);
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub const fn new_ecdsa(key: ECPrivateKey) -> Self {
        Self::ECDSA(key)
    }

    /// Creates a new Ed25519 signing private key from an `Ed25519PrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The Ed25519 private key to use
    ///
    /// # Returns
    ///
    /// A new Ed25519 signing private key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ed25519")]
    /// # {
    /// use bc_components::{Ed25519PrivateKey, SigningPrivateKey};
    ///
    /// // Create a new Ed25519 private key
    /// let ed_key = Ed25519PrivateKey::new();
    ///
    /// // Create an Ed25519 signing key from it
    /// let signing_key = SigningPrivateKey::new_ed25519(ed_key);
    /// # }
    /// ```
    #[cfg(feature = "ed25519")]
    pub const fn new_ed25519(key: Ed25519PrivateKey) -> Self {
        Self::Ed25519(key)
    }

    /// Creates a new SSH signing private key from an `SSHPrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The SSH private key to use
    ///
    /// # Returns
    ///
    /// A new SSH signing private key
    #[cfg(feature = "ssh")]
    pub fn new_ssh(key: SSHPrivateKey) -> Self {
        Self::SSH(Box::new(key))
    }

    /// Returns the underlying Schnorr private key if this is a Schnorr key.
    ///
    /// # Returns
    ///
    /// Some reference to the EC private key if this is a Schnorr key,
    /// or None if it's a different key type.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{ECPrivateKey, SigningPrivateKey};
    ///
    /// // Create a Schnorr key
    /// let schnorr_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
    /// assert!(schnorr_key.to_schnorr().is_some());
    ///
    /// // Create an ECDSA key
    /// let ecdsa_key = SigningPrivateKey::new_ecdsa(ECPrivateKey::new());
    /// assert!(ecdsa_key.to_schnorr().is_none());
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn to_schnorr(&self) -> Option<&ECPrivateKey> {
        match self {
            Self::Schnorr(key) => Some(key),
            _ => None,
        }
    }

    /// Checks if this is a Schnorr signing key.
    ///
    /// # Returns
    ///
    /// `true` if this is a Schnorr key, `false` otherwise
    #[cfg(feature = "secp256k1")]
    pub fn is_schnorr(&self) -> bool {
        self.to_schnorr().is_some()
    }

    /// Returns the underlying ECDSA private key if this is an ECDSA key.
    ///
    /// # Returns
    ///
    /// Some reference to the EC private key if this is an ECDSA key,
    /// or None if it's a different key type.
    #[cfg(feature = "secp256k1")]
    pub fn to_ecdsa(&self) -> Option<&ECPrivateKey> {
        match self {
            Self::ECDSA(key) => Some(key),
            _ => None,
        }
    }

    /// Checks if this is an ECDSA signing key.
    ///
    /// # Returns
    ///
    /// `true` if this is an ECDSA key, `false` otherwise
    #[cfg(feature = "secp256k1")]
    pub fn is_ecdsa(&self) -> bool {
        self.to_ecdsa().is_some()
    }

    /// Returns the underlying SSH private key if this is an SSH key.
    ///
    /// # Returns
    ///
    /// Some reference to the SSH private key if this is an SSH key,
    /// or None if it's a different key type.
    #[cfg(feature = "ssh")]
    pub fn to_ssh(&self) -> Option<&SSHPrivateKey> {
        match self {
            Self::SSH(key) => Some(key),
            _ => None,
        }
    }

    /// Checks if this is an SSH signing key.
    ///
    /// # Returns
    ///
    /// `true` if this is an SSH key, `false` otherwise
    #[cfg(feature = "ssh")]
    pub fn is_ssh(&self) -> bool {
        self.to_ssh().is_some()
    }

    /// Derives the corresponding public key for this private key.
    ///
    /// # Returns
    ///
    /// A `Result` containing the public key, or an error if the public key
    /// cannot be derived (e.g., for MLDSA keys).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{ECPrivateKey, SigningPrivateKey};
    ///
    /// // Create a Schnorr signing key
    /// let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
    ///
    /// // Derive the public key
    /// let public_key = private_key.public_key().unwrap();
    /// # }
    /// ```
    #[allow(unreachable_patterns)]
    pub fn public_key(&self) -> Result<SigningPublicKey> {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr(key) => {
                Ok(SigningPublicKey::from_schnorr(key.schnorr_public_key()))
            }
            #[cfg(feature = "secp256k1")]
            Self::ECDSA(key) => {
                Ok(SigningPublicKey::from_ecdsa(key.public_key()))
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => {
                Ok(SigningPublicKey::from_ed25519(key.public_key()))
            }
            #[cfg(feature = "ssh")]
            Self::SSH(key) => {
                Ok(SigningPublicKey::from_ssh(key.public_key().clone()))
            }
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA(_) => {
                Err(Error::general("Deriving MLDSA public key not supported"))
            }
            #[cfg(not(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "ssh",
                feature = "pqcrypto"
            )))]
            _ => unreachable!(),
        }
    }
}

impl SigningPrivateKey {
    /// Signs a message using ECDSA.
    ///
    /// This method is only valid for ECDSA keys.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A `Result` containing the ECDSA signature, or an error if the key is not
    /// an ECDSA key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{ECPrivateKey, Signer, SigningPrivateKey};
    ///
    /// // Create an ECDSA key
    /// let private_key = SigningPrivateKey::new_ecdsa(ECPrivateKey::new());
    ///
    /// // Sign a message
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    fn ecdsa_sign(&self, message: impl AsRef<[u8]>) -> Result<Signature> {
        if let Some(private_key) = self.to_ecdsa() {
            let sig = private_key.ecdsa_sign(message);
            Ok(Signature::ecdsa_from_data(sig))
        } else {
            Err(Error::crypto("Invalid key type for ECDSA signing"))
        }
    }

    /// Signs a message using Schnorr with the provided random number generator.
    ///
    /// This method is only valid for Schnorr keys.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `rng` - The random number generator to use for signature creation
    ///
    /// # Returns
    ///
    /// A `Result` containing the Schnorr signature, or an error if the key is
    /// not a Schnorr key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use std::{cell::RefCell, rc::Rc};
    ///
    /// use bc_components::{ECPrivateKey, SigningPrivateKey};
    /// use bc_rand::SecureRandomNumberGenerator;
    ///
    /// // Create a Schnorr key
    /// let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
    ///
    /// // Create an RNG
    /// let rng = Rc::new(RefCell::new(SecureRandomNumberGenerator));
    ///
    /// // Sign a message
    /// let message = b"Hello, world!";
    /// let signature = private_key.schnorr_sign(&message, rng).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn schnorr_sign(
        &self,
        message: impl AsRef<[u8]>,
        rng: Rc<RefCell<dyn RandomNumberGenerator>>,
    ) -> Result<Signature> {
        if let Some(private_key) = self.to_schnorr() {
            let sig =
                private_key.schnorr_sign_using(message, &mut *rng.borrow_mut());
            Ok(Signature::schnorr_from_data(sig))
        } else {
            Err(Error::crypto("Invalid key type for Schnorr signing"))
        }
    }

    /// Signs a message using Ed25519.
    ///
    /// This method is only valid for Ed25519 keys.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A `Result` containing the Ed25519 signature, or an error if the key is
    /// not an Ed25519 key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ed25519")]
    /// # {
    /// use bc_components::{Ed25519PrivateKey, Signer, SigningPrivateKey};
    ///
    /// // Create an Ed25519 key
    /// let private_key = SigningPrivateKey::new_ed25519(Ed25519PrivateKey::new());
    ///
    /// // Sign a message
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "ed25519")]
    pub fn ed25519_sign(&self, message: impl AsRef<[u8]>) -> Result<Signature> {
        #[cfg(any(
            feature = "secp256k1",
            feature = "ssh",
            feature = "pqcrypto"
        ))]
        if let Self::Ed25519(key) = self {
            let sig = key.sign(message.as_ref());
            Ok(Signature::ed25519_from_data(sig))
        } else {
            Err(Error::crypto("Invalid key type for Ed25519 signing"))
        }
        #[cfg(not(any(
            feature = "secp256k1",
            feature = "ssh",
            feature = "pqcrypto"
        )))]
        {
            let Self::Ed25519(key) = self;
            let sig = key.sign(message.as_ref());
            Ok(Signature::ed25519_from_data(sig))
        }
    }

    /// Signs a message using SSH.
    ///
    /// This method is only valid for SSH keys.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `namespace` - The SSH namespace string
    /// * `hash_alg` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// A `Result` containing the SSH signature, or an error if the key is not
    /// an SSH key.
    #[cfg(feature = "ssh")]
    fn ssh_sign(
        &self,
        message: impl AsRef<[u8]>,
        namespace: impl AsRef<str>,
        hash_alg: HashAlg,
    ) -> Result<Signature> {
        if let Some(private) = self.to_ssh() {
            let sig =
                private.sign(namespace.as_ref(), hash_alg, message.as_ref())?;
            Ok(Signature::from_ssh(sig))
        } else {
            Err(Error::ssh("Invalid key type for SSH signing"))
        }
    }

    /// Signs a message using ML-DSA.
    ///
    /// This method is only valid for ML-DSA keys.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A `Result` containing the ML-DSA signature, or an error if the key is
    /// not an ML-DSA key.
    #[cfg(feature = "pqcrypto")]
    #[allow(irrefutable_let_patterns)]
    fn mldsa_sign(&self, message: impl AsRef<[u8]>) -> Result<Signature> {
        if let Self::MLDSA(key) = self {
            let sig = key.sign(message.as_ref());
            Ok(Signature::MLDSA(sig))
        } else {
            Err(Error::post_quantum("Invalid key type for MLDSA signing"))
        }
    }
}

/// Implementation of the Signer trait for SigningPrivateKey
impl Signer for SigningPrivateKey {
    /// Signs a message with the appropriate algorithm based on the key type.
    ///
    /// This method dispatches to the appropriate signing method based on the
    /// key type and provided options.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `options` - Optional signing options (algorithm-specific parameters)
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature, or an error if signing fails
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # // Requires secp256k1 feature (enabled by default)
    /// use std::{cell::RefCell, rc::Rc};
    ///
    /// use bc_components::{
    ///     ECPrivateKey, Signer, SigningOptions, SigningPrivateKey,
    /// };
    /// use bc_rand::SecureRandomNumberGenerator;
    ///
    /// // Create a Schnorr key
    /// let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
    ///
    /// // Create Schnorr signing options
    /// let rng = Rc::new(RefCell::new(SecureRandomNumberGenerator));
    /// let options = SigningOptions::Schnorr { rng };
    ///
    /// // Sign a message with options
    /// let message = b"Hello, world!";
    /// let signature = private_key
    ///     .sign_with_options(&message, Some(options))
    ///     .unwrap();
    /// ```
    #[allow(unreachable_patterns)]
    fn sign_with_options(
        &self,
        _message: &dyn AsRef<[u8]>,
        #[cfg_attr(
            not(any(feature = "secp256k1", feature = "ssh")),
            allow(unused_variables)
        )]
        options: Option<SigningOptions>,
    ) -> Result<Signature> {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr(_) => {
                if let Some(SigningOptions::Schnorr { rng }) = options {
                    self.schnorr_sign(_message, rng)
                } else {
                    self.schnorr_sign(
                        _message,
                        Rc::new(RefCell::new(SecureRandomNumberGenerator)),
                    )
                }
            }
            #[cfg(feature = "secp256k1")]
            Self::ECDSA(_) => self.ecdsa_sign(_message),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(_) => self.ed25519_sign(_message),
            #[cfg(feature = "ssh")]
            Self::SSH(_) => {
                if let Some(SigningOptions::Ssh { namespace, hash_alg }) =
                    options
                {
                    self.ssh_sign(_message, namespace, hash_alg)
                } else {
                    Err(Error::ssh(
                        "Missing namespace and hash algorithm for SSH signing",
                    ))
                }
            }
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA(_) => self.mldsa_sign(_message),
            #[cfg(not(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "ssh",
                feature = "pqcrypto"
            )))]
            _ => unreachable!(),
        }
    }
}

/// Implementation of the Verifier trait for SigningPrivateKey
impl Verifier for SigningPrivateKey {
    /// Verifies a signature against a message.
    ///
    /// This method is only implemented for Schnorr keys, where it derives the
    /// public key and uses it to verify the signature. For other key types,
    /// this method always returns `false`.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify
    /// * `message` - The message that was allegedly signed
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the message, `false` otherwise
    fn verify(
        &self,
        _signature: &Signature,
        _message: &dyn AsRef<[u8]>,
    ) -> bool {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr(key) => {
                if let Signature::Schnorr(sig) = _signature {
                    key.schnorr_public_key().schnorr_verify(sig, _message)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

/// Implementation of the CBORTagged trait for SigningPrivateKey
impl CBORTagged for SigningPrivateKey {
    /// Returns the CBOR tags used for this type.
    ///
    /// For SigningPrivateKey, the tag is 40021.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SIGNING_PRIVATE_KEY])
    }
}

/// Conversion from SigningPrivateKey to CBOR
impl From<SigningPrivateKey> for CBOR {
    /// Converts a SigningPrivateKey to a tagged CBOR value.
    fn from(value: SigningPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

/// Implementation of the CBORTaggedEncodable trait for SigningPrivateKey
impl CBORTaggedEncodable for SigningPrivateKey {
    /// Converts the SigningPrivateKey to an untagged CBOR value.
    ///
    /// The CBOR encoding depends on the key type:
    ///
    /// - Schnorr: A byte string containing the 32-byte private key
    /// - ECDSA: An array containing the discriminator 1 and the 32-byte private
    ///   key
    /// - Ed25519: An array containing the discriminator 2 and the 32-byte
    ///   private key
    /// - SSH: A tagged text string containing the OpenSSH-encoded private key
    /// - ML-DSA: Delegates to the MLDSAPrivateKey implementation
    fn untagged_cbor(&self) -> CBOR {
        match self {
            #[cfg(feature = "secp256k1")]
            SigningPrivateKey::Schnorr(key) => CBOR::to_byte_string(key.data()),
            #[cfg(feature = "secp256k1")]
            SigningPrivateKey::ECDSA(key) => {
                vec![(1).into(), CBOR::to_byte_string(key.data())].into()
            }
            #[cfg(feature = "ed25519")]
            SigningPrivateKey::Ed25519(key) => {
                vec![(2).into(), CBOR::to_byte_string(key.data())].into()
            }
            #[cfg(feature = "ssh")]
            SigningPrivateKey::SSH(key) => {
                let string = key.to_openssh(LineEnding::LF).unwrap();
                CBOR::to_tagged_value(
                    tags::TAG_SSH_TEXT_PRIVATE_KEY,
                    (*string).clone(),
                )
            }
            #[cfg(feature = "pqcrypto")]
            SigningPrivateKey::MLDSA(key) => key.clone().into(),
            #[cfg(not(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "ssh",
                feature = "pqcrypto"
            )))]
            _ => unreachable!(),
        }
    }
}

/// TryFrom implementation for converting CBOR to SigningPrivateKey
impl TryFrom<CBOR> for SigningPrivateKey {
    type Error = dcbor::Error;

    /// Tries to convert a CBOR value to a SigningPrivateKey.
    ///
    /// This is a convenience method that calls from_tagged_cbor.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implementation of the CBORTaggedDecodable trait for SigningPrivateKey
impl CBORTaggedDecodable for SigningPrivateKey {
    /// Creates a SigningPrivateKey from an untagged CBOR value.
    ///
    /// # Arguments
    ///
    /// * `untagged_cbor` - The CBOR value to decode
    ///
    /// # Returns
    ///
    /// A Result containing the decoded SigningPrivateKey or an error if
    /// decoding fails.
    ///
    /// # Format
    ///
    /// The CBOR value must be one of:
    /// - A byte string (interpreted as a Schnorr private key)
    /// - An array where the first element is a discriminator (1 for ECDSA, 2
    ///   for Ed25519) and the second element is a byte string containing the
    ///   key data
    /// - A tagged value with a tag for ML-DSA or SSH keys
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.into_case() {
            CBORCase::ByteString(data) => {
                #[cfg(feature = "secp256k1")]
                {
                    Ok(Self::Schnorr(ECPrivateKey::from_data_ref(data)?))
                }
                #[cfg(not(feature = "secp256k1"))]
                {
                    let _ = data;
                    Err("Schnorr private key not available without secp256k1 feature".into())
                }
            }
            CBORCase::Array(mut elements) => {
                let discriminator = usize::try_from(elements.remove(0))?;
                match discriminator {
                    #[cfg(feature = "secp256k1")]
                    1 => {
                        let data = elements.remove(0).try_into_byte_string()?;
                        let key = ECPrivateKey::from_data_ref(data)?;
                        Ok(Self::ECDSA(key))
                    }
                    #[cfg(feature = "ed25519")]
                    2 => {
                        let data = elements.remove(0).try_into_byte_string()?;
                        let key = Ed25519PrivateKey::from_data_ref(data)?;
                        Ok(Self::Ed25519(key))
                    }
                    _ => Err(format!(
                        "Invalid discriminator for SigningPrivateKey: {}",
                        discriminator
                    )
                    .into()),
                }
            }
            #[cfg_attr(
                not(any(feature = "ssh", feature = "pqcrypto")),
                allow(unused_variables)
            )]
            CBORCase::Tagged(tag, item) => {
                let value = tag.value();
                match value {
                    #[cfg(feature = "ssh")]
                    tags::TAG_SSH_TEXT_PRIVATE_KEY => {
                        let string = item.try_into_text()?;
                        let key = SSHPrivateKey::from_openssh(string).map_err(
                            |_| dcbor::Error::msg("Invalid SSH private key"),
                        )?;
                        Ok(Self::SSH(Box::new(key)))
                    }
                    #[cfg(feature = "pqcrypto")]
                    tags::TAG_MLDSA_PRIVATE_KEY => {
                        let key = MLDSAPrivateKey::from_untagged_cbor(item)?;
                        Ok(Self::MLDSA(key))
                    }
                    _ => Err(format!(
                        "Invalid CBOR tag for SigningPrivateKey: {value}"
                    )
                    .into()),
                }
            }
            _ => Err("Invalid CBOR case for SigningPrivateKey".into()),
        }
    }
}

/// Debug implementation for SigningPrivateKey
impl std::fmt::Debug for SigningPrivateKey {
    /// Formats the SigningPrivateKey for display.
    ///
    /// For security reasons, the private key data is not displayed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningPrivateKey")
    }
}

/// Implementation of the From trait for reference to SigningPrivateKey
impl From<&SigningPrivateKey> for SigningPrivateKey {
    /// Clones a SigningPrivateKey from a reference.
    fn from(key: &SigningPrivateKey) -> Self {
        key.clone()
    }
}

#[cfg(feature = "ssh")]
impl ReferenceProvider for SSHPrivateKey {
    fn reference(&self) -> Reference {
        let string = self.to_openssh(LineEnding::default()).unwrap();
        let bytes = string.as_bytes();
        let digest = Digest::from_image(bytes);
        Reference::from_digest(digest)
    }
}

impl ReferenceProvider for SigningPrivateKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl std::fmt::Display for SigningPrivateKey {
    #[allow(unreachable_patterns)]
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "ssh",
            feature = "pqcrypto"
        ))]
        {
            let display_key = match self {
                #[cfg(feature = "secp256k1")]
                SigningPrivateKey::Schnorr(key) => key.to_string(),
                #[cfg(feature = "secp256k1")]
                SigningPrivateKey::ECDSA(key) => key.to_string(),
                #[cfg(feature = "ed25519")]
                SigningPrivateKey::Ed25519(key) => key.to_string(),
                #[cfg(feature = "ssh")]
                SigningPrivateKey::SSH(key) => {
                    format!("SSHPrivateKey({})", key.ref_hex_short())
                }
                #[cfg(feature = "pqcrypto")]
                SigningPrivateKey::MLDSA(key) => key.to_string(),
                _ => unreachable!(),
            };
            write!(
                _f,
                "SigningPrivateKey({}, {})",
                self.ref_hex_short(),
                display_key
            )
        }
        #[cfg(not(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "ssh",
            feature = "pqcrypto"
        )))]
        {
            match *self {}
        }
    }
}
