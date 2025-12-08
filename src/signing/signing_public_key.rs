use bc_ur::prelude::*;
#[cfg(feature = "ssh")]
use ssh_key::public::PublicKey as SSHPublicKey;

#[cfg(feature = "ed25519")]
use crate::Ed25519PublicKey;
#[cfg(feature = "sr25519")]
use crate::Sr25519PublicKey;
#[cfg(feature = "pqcrypto")]
use crate::MLDSAPublicKey;
use crate::{Digest, Reference, ReferenceProvider, Signature, Verifier, tags};
#[cfg(feature = "secp256k1")]
use crate::{ECKeyBase, ECPublicKey, SchnorrPublicKey};

/// A public key used for verifying digital signatures.
///
/// `SigningPublicKey` is an enum representing different types of signing public
/// keys, including elliptic curve schemes (ECDSA, Schnorr), Edwards curve
/// schemes (Ed25519), post-quantum schemes (ML-DSA), and SSH keys.
///
/// This type implements the `Verifier` trait, allowing it to verify signatures
/// of the appropriate type.
///
/// # Examples
///
/// Creating and using a signing public key pair:
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{SignatureScheme, Signer, Verifier};
///
/// // Create a key pair
/// let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
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
/// `SigningPublicKey` can be serialized to and from CBOR with appropriate tags:
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{SignatureScheme, SigningPublicKey};
/// use dcbor::prelude::*;
///
/// // Create a key pair and get the public key
/// let (_, public_key) = SignatureScheme::Schnorr.keypair();
///
/// // Convert to CBOR
/// let cbor: CBOR = public_key.clone().into();
/// let data = cbor.to_cbor_data();
///
/// // Convert back from CBOR
/// let recovered = SigningPublicKey::from_tagged_cbor_data(&data).unwrap();
///
/// // The keys should be equal
/// assert_eq!(public_key, recovered);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SigningPublicKey {
    /// A Schnorr public key (BIP-340, x-only)
    #[cfg(feature = "secp256k1")]
    Schnorr(SchnorrPublicKey),

    /// An ECDSA public key (compressed, 33 bytes)
    #[cfg(feature = "secp256k1")]
    ECDSA(ECPublicKey),

    /// An Ed25519 public key
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519PublicKey),

    /// An SR25519 (Schnorr-Ristretto) public key
    #[cfg(feature = "sr25519")]
    Sr25519(Sr25519PublicKey),

    /// An SSH public key
    #[cfg(feature = "ssh")]
    SSH(SSHPublicKey),

    /// A post-quantum ML-DSA public key
    #[cfg(feature = "pqcrypto")]
    MLDSA(MLDSAPublicKey),
}

impl SigningPublicKey {
    /// Creates a new signing public key from a Schnorr public key.
    ///
    /// # Arguments
    ///
    /// * `key` - A BIP-340 Schnorr public key
    ///
    /// # Returns
    ///
    /// A new signing public key containing the Schnorr key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{SchnorrPublicKey, SigningPublicKey};
    ///
    /// // Create a Schnorr public key
    /// let schnorr_key = SchnorrPublicKey::from_data([0u8; 32]);
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_schnorr(schnorr_key);
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn from_schnorr(key: SchnorrPublicKey) -> Self { Self::Schnorr(key) }

    /// Creates a new signing public key from an ECDSA public key.
    ///
    /// # Arguments
    ///
    /// * `key` - A compressed ECDSA public key
    ///
    /// # Returns
    ///
    /// A new signing public key containing the ECDSA key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{ECKey, ECPrivateKey, SigningPublicKey};
    ///
    /// // Create an EC private key and derive its public key
    /// let private_key = ECPrivateKey::new();
    /// let public_key = private_key.public_key();
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_ecdsa(public_key);
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn from_ecdsa(key: ECPublicKey) -> Self { Self::ECDSA(key) }

    /// Creates a new signing public key from an Ed25519 public key.
    ///
    /// # Arguments
    ///
    /// * `key` - An Ed25519 public key
    ///
    /// # Returns
    ///
    /// A new signing public key containing the Ed25519 key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ed25519")]
    /// # {
    /// use bc_components::{Ed25519PrivateKey, SigningPublicKey};
    ///
    /// // Create an Ed25519 private key and get its public key
    /// let private_key = Ed25519PrivateKey::new();
    /// let public_key = private_key.public_key();
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_ed25519(public_key);
    /// # }
    /// ```
    #[cfg(feature = "ed25519")]
    pub fn from_ed25519(key: Ed25519PublicKey) -> Self { Self::Ed25519(key) }

    /// Creates a new signing public key from an SR25519 public key.
    ///
    /// # Arguments
    ///
    /// * `key` - An SR25519 public key
    ///
    /// # Returns
    ///
    /// A new signing public key containing the SR25519 key
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "sr25519")]
    /// # {
    /// use bc_components::{Sr25519PrivateKey, SigningPublicKey};
    ///
    /// // Create an SR25519 private key and get its public key
    /// let private_key = Sr25519PrivateKey::new();
    /// let public_key = private_key.public_key();
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_sr25519(public_key);
    /// # }
    /// ```
    #[cfg(feature = "sr25519")]
    pub fn from_sr25519(key: Sr25519PublicKey) -> Self { Self::Sr25519(key) }

    /// Creates a new signing public key from an SSH public key.
    ///
    /// # Arguments
    ///
    /// * `key` - An SSH public key
    ///
    /// # Returns
    ///
    /// A new signing public key containing the SSH key
    #[cfg(feature = "ssh")]
    pub fn from_ssh(key: SSHPublicKey) -> Self { Self::SSH(key) }

    /// Returns the underlying Schnorr public key if this is a Schnorr key.
    ///
    /// # Returns
    ///
    /// Some reference to the Schnorr public key if this is a Schnorr key,
    /// or None if it's a different key type.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{SignatureScheme, Signer};
    ///
    /// // Create a Schnorr key pair
    /// let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
    ///
    /// // We can access the Schnorr public key
    /// assert!(public_key.to_schnorr().is_some());
    ///
    /// // Create an ECDSA key pair
    /// let (_, ecdsa_public) = SignatureScheme::Ecdsa.keypair();
    ///
    /// // This will return None since it's not a Schnorr key
    /// assert!(ecdsa_public.to_schnorr().is_none());
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn to_schnorr(&self) -> Option<&SchnorrPublicKey> {
        match self {
            Self::Schnorr(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the underlying ECDSA public key if this is an ECDSA key.
    ///
    /// # Returns
    ///
    /// Some reference to the ECDSA public key if this is an ECDSA key,
    /// or None if it's a different key type.
    #[cfg(feature = "secp256k1")]
    pub fn to_ecdsa(&self) -> Option<&ECPublicKey> {
        match self {
            Self::ECDSA(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the underlying SSH public key if this is an SSH key.
    ///
    /// # Returns
    ///
    /// Some reference to the SSH public key if this is an SSH key,
    /// or None if it's a different key type.
    #[cfg(feature = "ssh")]
    pub fn to_ssh(&self) -> Option<&SSHPublicKey> {
        match self {
            Self::SSH(key) => Some(key),
            #[cfg(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "pqcrypto"
            ))]
            _ => None,
        }
    }
}

/// Implementation of the Verifier trait for SigningPublicKey
impl Verifier for SigningPublicKey {
    /// Verifies a signature against a message.
    ///
    /// The type of signature must match the type of this key, and the
    /// signature must be valid for the message, or the verification
    /// will fail.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify
    /// * `message` - The message that was allegedly signed
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the message, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # // Requires secp256k1 feature (enabled by default)
    /// use bc_components::{SignatureScheme, Signer, Verifier};
    ///
    /// // Create a key pair
    /// let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
    ///
    /// // Sign a message
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    ///
    /// // Verify the signature with the correct message (should succeed)
    /// assert!(public_key.verify(&signature, &message));
    ///
    /// // Verify the signature with an incorrect message (should fail)
    /// assert!(!public_key.verify(&signature, &b"Tampered message"));
    /// ```
    #[allow(unreachable_patterns)]
    fn verify(
        &self,
        _signature: &Signature,
        _message: &dyn AsRef<[u8]>,
    ) -> bool {
        match self {
            #[cfg(feature = "secp256k1")]
            SigningPublicKey::Schnorr(key) => match _signature {
                Signature::Schnorr(sig) => key.schnorr_verify(sig, _message),
                _ => false,
            },
            #[cfg(feature = "secp256k1")]
            SigningPublicKey::ECDSA(key) => match _signature {
                Signature::ECDSA(sig) => key.verify(sig, _message),
                _ => false,
            },
            #[cfg(feature = "ed25519")]
            SigningPublicKey::Ed25519(key) => match _signature {
                Signature::Ed25519(sig) => key.verify(sig, _message),
                #[cfg(any(
                    feature = "secp256k1",
                    feature = "sr25519",
                    feature = "ssh",
                    feature = "pqcrypto"
                ))]
                _ => false,
            },
            #[cfg(feature = "sr25519")]
            SigningPublicKey::Sr25519(key) => match _signature {
                Signature::Sr25519(sig) => key.verify(sig, _message),
                #[cfg(any(
                    feature = "secp256k1",
                    feature = "ed25519",
                    feature = "ssh",
                    feature = "pqcrypto"
                ))]
                _ => false,
            },
            #[cfg(feature = "ssh")]
            SigningPublicKey::SSH(key) => match _signature {
                Signature::SSH(sig) => {
                    key.verify(sig.namespace(), _message.as_ref(), sig).is_ok()
                }
                _ => false,
            },
            #[cfg(feature = "pqcrypto")]
            SigningPublicKey::MLDSA(key) => match _signature {
                Signature::MLDSA(sig) => key
                    .verify(sig, _message)
                    .map_err(|_| false)
                    .unwrap_or(false),
                _ => false,
            },
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

/// Implementation of AsRef for SigningPublicKey
impl AsRef<SigningPublicKey> for SigningPublicKey {
    /// Returns a reference to self.
    fn as_ref(&self) -> &SigningPublicKey { self }
}

/// Implementation of the CBORTagged trait for SigningPublicKey
impl CBORTagged for SigningPublicKey {
    /// Returns the CBOR tags used for this type.
    ///
    /// For SigningPublicKey, the tag is 40022.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SIGNING_PUBLIC_KEY])
    }
}

/// Conversion from SigningPublicKey to CBOR
impl From<SigningPublicKey> for CBOR {
    /// Converts a SigningPublicKey to a tagged CBOR value.
    fn from(value: SigningPublicKey) -> Self { value.tagged_cbor() }
}

/// Implementation of the CBORTaggedEncodable trait for SigningPublicKey
impl CBORTaggedEncodable for SigningPublicKey {
    /// Converts the SigningPublicKey to an untagged CBOR value.
    ///
    /// The CBOR encoding depends on the key type:
    ///
    /// - Schnorr: A byte string containing the 32-byte x-only public key
    /// - ECDSA: An array containing the discriminator 1 and the 33-byte
    ///   compressed public key
    /// - Ed25519: An array containing the discriminator 2 and the 32-byte
    ///   public key
    /// - SSH: A tagged text string containing the OpenSSH-encoded public key
    /// - ML-DSA: Delegates to the MLDSAPublicKey implementation
    #[allow(unreachable_patterns)]
    fn untagged_cbor(&self) -> CBOR {
        match self {
            #[cfg(feature = "secp256k1")]
            SigningPublicKey::Schnorr(key) => CBOR::to_byte_string(key.data()),
            #[cfg(feature = "secp256k1")]
            SigningPublicKey::ECDSA(key) => {
                vec![(1).into(), CBOR::to_byte_string(key.data())].into()
            }
            #[cfg(feature = "ed25519")]
            SigningPublicKey::Ed25519(key) => {
                vec![(2).into(), CBOR::to_byte_string(key.data())].into()
            }
            #[cfg(feature = "sr25519")]
            SigningPublicKey::Sr25519(key) => {
                vec![(3).into(), CBOR::to_byte_string(key.data())].into()
            }
            #[cfg(feature = "ssh")]
            SigningPublicKey::SSH(key) => {
                let string = key.to_openssh().unwrap();
                CBOR::to_tagged_value(tags::TAG_SSH_TEXT_PUBLIC_KEY, string)
            }
            #[cfg(feature = "pqcrypto")]
            SigningPublicKey::MLDSA(key) => key.clone().into(),
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

/// TryFrom implementation for converting CBOR to SigningPublicKey
impl TryFrom<CBOR> for SigningPublicKey {
    type Error = dcbor::Error;

    /// Tries to convert a CBOR value to a SigningPublicKey.
    ///
    /// This is a convenience method that calls from_tagged_cbor.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implementation of the CBORTaggedDecodable trait for SigningPublicKey
impl CBORTaggedDecodable for SigningPublicKey {
    /// Creates a SigningPublicKey from an untagged CBOR value.
    ///
    /// # Arguments
    ///
    /// * `untagged_cbor` - The CBOR value to decode
    ///
    /// # Returns
    ///
    /// A Result containing the decoded SigningPublicKey or an error if decoding
    /// fails.
    ///
    /// # Format
    ///
    /// The CBOR value must be one of:
    /// - A byte string (interpreted as a Schnorr public key)
    /// - An array of length 2, where the first element is a discriminator (1
    ///   for ECDSA, 2 for Ed25519) and the second element is a byte string
    ///   containing the key data
    /// - A tagged value with a tag for ML-DSA or SSH keys
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.clone().into_case() {
            CBORCase::ByteString(data) => {
                #[cfg(feature = "secp256k1")]
                {
                    Ok(Self::Schnorr(SchnorrPublicKey::from_data_ref(data)?))
                }
                #[cfg(not(feature = "secp256k1"))]
                {
                    let _ = data;
                    Err("Schnorr public key not available without secp256k1 feature".into())
                }
            }
            CBORCase::Array(mut elements) => {
                if elements.len() == 2 {
                    let mut drain = elements.drain(0..);
                    let ele_0 = drain.next().unwrap().into_case();
                    #[cfg_attr(
                        not(any(feature = "secp256k1", feature = "ed25519")),
                        allow(unused_variables)
                    )]
                    let ele_1 = drain.next().unwrap().into_case();
                    #[cfg(feature = "secp256k1")]
                    if let CBORCase::Unsigned(1) = ele_0
                        && let CBORCase::ByteString(data) = ele_1
                    {
                        return Ok(Self::ECDSA(ECPublicKey::from_data_ref(
                            data,
                        )?));
                    }
                    #[cfg(not(feature = "secp256k1"))]
                    let _ = ele_0;
                    #[cfg(feature = "ed25519")]
                    if let CBORCase::Unsigned(2) = ele_0
                        && let CBORCase::ByteString(data) = ele_1
                    {
                        return Ok(Self::Ed25519(
                            Ed25519PublicKey::from_data_ref(data)?,
                        ));
                    }
                }
                Err("invalid signing public key".into())
            }
            #[cfg_attr(not(feature = "ssh"), allow(unused_variables))]
            CBORCase::Tagged(tag, item) => match tag.value() {
                #[cfg(feature = "ssh")]
                tags::TAG_SSH_TEXT_PUBLIC_KEY => {
                    let string = item.try_into_text()?;
                    let key = SSHPublicKey::from_openssh(&string)
                        .map_err(|_| "invalid SSH public key")?;
                    Ok(Self::SSH(key))
                }
                #[cfg(feature = "pqcrypto")]
                tags::TAG_MLDSA_PUBLIC_KEY => {
                    let key = MLDSAPublicKey::from_tagged_cbor(untagged_cbor)?;
                    Ok(Self::MLDSA(key))
                }
                _ => Err("invalid signing public key".into()),
            },
            _ => Err("invalid signing public key".into()),
        }
    }
}

#[cfg(feature = "ssh")]
impl ReferenceProvider for SSHPublicKey {
    fn reference(&self) -> Reference {
        let string = self.to_openssh().unwrap();
        let bytes = string.as_bytes();
        let digest = Digest::from_image(bytes);
        Reference::from_digest(digest)
    }
}

impl ReferenceProvider for SigningPublicKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl std::fmt::Display for SigningPublicKey {
    #[allow(unreachable_patterns)]
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "sr25519",
            feature = "ssh",
            feature = "pqcrypto"
        ))]
        {
            let display_key = match self {
                #[cfg(feature = "secp256k1")]
                SigningPublicKey::Schnorr(key) => key.to_string(),
                #[cfg(feature = "secp256k1")]
                SigningPublicKey::ECDSA(key) => key.to_string(),
                #[cfg(feature = "ed25519")]
                SigningPublicKey::Ed25519(key) => key.to_string(),
                #[cfg(feature = "ssh")]
                SigningPublicKey::SSH(key) => {
                    format!("SSHPublicKey({})", key.ref_hex_short())
                }
                #[cfg(feature = "pqcrypto")]
                SigningPublicKey::MLDSA(key) => key.to_string(),
                _ => unreachable!(),
            };
            write!(
                _f,
                "SigningPublicKey({}, {})",
                self.ref_hex_short(),
                display_key
            )
        }
        #[cfg(not(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "sr25519",
            feature = "ssh",
            feature = "pqcrypto"
        )))]
        {
            match *self {}
        }
    }
}
