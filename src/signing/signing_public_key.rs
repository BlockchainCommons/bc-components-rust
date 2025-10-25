use bc_ur::prelude::*;
use ssh_key::public::PublicKey as SSHPublicKey;

use crate::{
    tags, Digest, ECKeyBase, ECPublicKey, Ed25519PublicKey, MLDSAPublicKey, Reference, ReferenceProvider, SchnorrPublicKey, Signature, Verifier
};

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
/// ```
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
/// ```
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
    Schnorr(SchnorrPublicKey),

    /// An ECDSA public key (compressed, 33 bytes)
    ECDSA(ECPublicKey),

    /// An Ed25519 public key
    Ed25519(Ed25519PublicKey),

    /// An SSH public key
    SSH(SSHPublicKey),

    /// A post-quantum ML-DSA public key
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
    /// use bc_components::{SchnorrPublicKey, SigningPublicKey};
    ///
    /// // Create a Schnorr public key
    /// let schnorr_key = SchnorrPublicKey::from_data([0u8; 32]);
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_schnorr(schnorr_key);
    /// ```
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
    /// use bc_components::{ECKey, ECPrivateKey, SigningPublicKey};
    ///
    /// // Create an EC private key and derive its public key
    /// let private_key = ECPrivateKey::new();
    /// let public_key = private_key.public_key();
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_ecdsa(public_key);
    /// ```
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
    /// use bc_components::{Ed25519PrivateKey, SigningPublicKey};
    ///
    /// // Create an Ed25519 private key and get its public key
    /// let private_key = Ed25519PrivateKey::new();
    /// let public_key = private_key.public_key();
    ///
    /// // Create a signing public key from it
    /// let signing_key = SigningPublicKey::from_ed25519(public_key);
    /// ```
    pub fn from_ed25519(key: Ed25519PublicKey) -> Self { Self::Ed25519(key) }

    /// Creates a new signing public key from an SSH public key.
    ///
    /// # Arguments
    ///
    /// * `key` - An SSH public key
    ///
    /// # Returns
    ///
    /// A new signing public key containing the SSH key
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
    /// ```
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
    pub fn to_ssh(&self) -> Option<&SSHPublicKey> {
        match self {
            Self::SSH(key) => Some(key),
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
    /// ```
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
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        match self {
            SigningPublicKey::Schnorr(key) => match signature {
                Signature::Schnorr(sig) => key.schnorr_verify(sig, message),
                _ => false,
            },
            SigningPublicKey::ECDSA(key) => match signature {
                Signature::ECDSA(sig) => key.verify(sig, message),
                _ => false,
            },
            SigningPublicKey::Ed25519(key) => match signature {
                Signature::Ed25519(sig) => key.verify(sig, message),
                _ => false,
            },
            SigningPublicKey::SSH(key) => match signature {
                Signature::SSH(sig) => {
                    key.verify(sig.namespace(), message.as_ref(), sig).is_ok()
                }
                _ => false,
            },
            SigningPublicKey::MLDSA(key) => match signature {
                Signature::MLDSA(sig) => {
                    key.verify(sig, message).map_err(|_| false).unwrap_or(false)
                }
                _ => false,
            },
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
    fn untagged_cbor(&self) -> CBOR {
        match self {
            SigningPublicKey::Schnorr(key) => CBOR::to_byte_string(key.data()),
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
            SigningPublicKey::MLDSA(key) => key.clone().into(),
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
                Ok(Self::Schnorr(SchnorrPublicKey::from_data_ref(data)?))
            }
            CBORCase::Array(mut elements) => {
                if elements.len() == 2 {
                    let mut drain = elements.drain(0..);
                    let ele_0 = drain.next().unwrap().into_case();
                    let ele_1 = drain.next().unwrap().into_case();
                    if let CBORCase::Unsigned(1) = ele_0 {
                        if let CBORCase::ByteString(data) = ele_1 {
                            return Ok(Self::ECDSA(
                                ECPublicKey::from_data_ref(data)?,
                            ));
                        }
                    } else if let CBORCase::Unsigned(2) = ele_0 {
                        if let CBORCase::ByteString(data) = ele_1 {
                            return Ok(Self::Ed25519(
                                Ed25519PublicKey::from_data_ref(data)?,
                            ));
                        }
                    }
                }
                Err("invalid signing public key".into())
            }
            CBORCase::Tagged(tag, item) => match tag.value() {
                tags::TAG_SSH_TEXT_PUBLIC_KEY => {
                    let string = item.try_into_text()?;
                    let key = SSHPublicKey::from_openssh(&string)
                        .map_err(|_| "invalid SSH public key")?;
                    Ok(Self::SSH(key))
                }
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_key = match self {
            SigningPublicKey::Schnorr(key) => key.to_string(),
            SigningPublicKey::ECDSA(key) => key.to_string(),
            SigningPublicKey::Ed25519(key) => key.to_string(),
            SigningPublicKey::SSH(key) => format!("SSHPublicKey({})", key.ref_hex_short()),
            SigningPublicKey::MLDSA(key) => key.to_string(),
        };
        write!(f, "SigningPublicKey({}, {})", self.ref_hex_short(), display_key)
    }
}
