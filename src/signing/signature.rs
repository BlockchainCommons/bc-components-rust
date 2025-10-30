use bc_crypto::ED25519_SIGNATURE_SIZE;
#[cfg(feature = "secp256k1")]
use bc_crypto::{ECDSA_SIGNATURE_SIZE, SCHNORR_SIGNATURE_SIZE};
use bc_ur::prelude::*;
#[cfg(feature = "ssh")]
use ssh_key::{LineEnding, SshSig};

use super::SignatureScheme;
#[cfg(feature = "pqcrypto")]
use crate::MLDSASignature;
use crate::{Error, Result, tags};

/// A digital signature created with various signature algorithms.
///
/// `Signature` is an enum representing different types of digital signatures:
///
/// - `Schnorr`: A BIP-340 Schnorr signature (64 bytes)
/// - `ECDSA`: An ECDSA signature using the secp256k1 curve (64 bytes)
/// - `Ed25519`: An Ed25519 signature (64 bytes)
/// - `SSH`: An SSH signature in various formats
/// - `MLDSA`: A post-quantum ML-DSA signature
///
/// Signatures can be serialized to and from CBOR with appropriate tags.
///
/// # Examples
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{SignatureScheme, Signer, Verifier};
///
/// // Create a key pair using Schnorr
/// let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.sign(&message).unwrap();
///
/// // The signature can be verified with the corresponding public key
/// assert!(public_key.verify(&signature, &message));
/// ```
///
/// Converting to and from CBOR:
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{SignatureScheme, Signer};
/// use dcbor::prelude::*;
///
/// // Create a signature
/// let (private_key, _) = SignatureScheme::Schnorr.keypair();
/// let message = b"Hello, world!";
/// let signature = private_key.sign(&message).unwrap();
///
/// // Convert to CBOR
/// let cbor: CBOR = signature.clone().into();
/// let data = cbor.to_cbor_data();
///
/// // Convert back from CBOR
/// let recovered =
///     bc_components::Signature::from_tagged_cbor_data(&data).unwrap();
///
/// // The signatures should be identical
/// assert_eq!(signature, recovered);
/// ```
#[derive(Clone)]
pub enum Signature {
    /// A BIP-340 Schnorr signature (64 bytes)
    #[cfg(feature = "secp256k1")]
    Schnorr([u8; SCHNORR_SIGNATURE_SIZE]),

    /// An ECDSA signature using the secp256k1 curve (64 bytes)
    #[cfg(feature = "secp256k1")]
    ECDSA([u8; ECDSA_SIGNATURE_SIZE]),

    /// An Ed25519 signature (64 bytes)
    Ed25519([u8; ED25519_SIGNATURE_SIZE]),

    /// An SSH signature
    #[cfg(feature = "ssh")]
    SSH(SshSig),

    /// A post-quantum ML-DSA signature
    #[cfg(feature = "pqcrypto")]
    MLDSA(MLDSASignature),
}

/// Implementation of equality comparison for Signature
impl PartialEq for Signature {
    /// Compares two signatures for equality.
    ///
    /// Signatures are equal if they have the same type and the same signature
    /// data. Signatures of different types (e.g., Schnorr vs ECDSA) are
    /// never equal.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(feature = "secp256k1")]
            (Self::Schnorr(a), Self::Schnorr(b)) => a == b,
            #[cfg(feature = "secp256k1")]
            (Self::ECDSA(a), Self::ECDSA(b)) => a == b,
            (Self::Ed25519(a), Self::Ed25519(b)) => a == b,
            #[cfg(feature = "ssh")]
            (Self::SSH(a), Self::SSH(b)) => a == b,
            #[cfg(feature = "pqcrypto")]
            (Self::MLDSA(a), Self::MLDSA(b)) => a.as_bytes() == b.as_bytes(),
            #[cfg(any(
                feature = "secp256k1",
                feature = "ssh",
                feature = "pqcrypto"
            ))]
            _ => false,
        }
    }
}

impl Signature {
    /// Creates a Schnorr signature from a 64-byte array.
    ///
    /// # Arguments
    ///
    /// * `data` - The 64-byte signature data
    ///
    /// # Returns
    ///
    /// A new Schnorr signature
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::Signature;
    ///
    /// let data = [0u8; 64]; // In practice, this would be a real signature
    /// let signature = Signature::schnorr_from_data(data);
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn schnorr_from_data(data: [u8; SCHNORR_SIGNATURE_SIZE]) -> Self {
        Self::Schnorr(data)
    }

    /// Creates a Schnorr signature from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the signature data
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature or an error if the data is not
    /// exactly 64 bytes in length.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::Signature;
    ///
    /// let data = vec![0u8; 64]; // In practice, this would be a real signature
    /// let signature = Signature::schnorr_from_data_ref(&data).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn schnorr_from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != SCHNORR_SIGNATURE_SIZE {
            return Err(Error::invalid_size(
                "Schnorr signature",
                SCHNORR_SIGNATURE_SIZE,
                data.len(),
            ));
        }
        let mut arr = [0u8; SCHNORR_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::schnorr_from_data(arr))
    }

    /// Creates an ECDSA signature from a 64-byte array.
    ///
    /// # Arguments
    ///
    /// * `data` - The 64-byte signature data
    ///
    /// # Returns
    ///
    /// A new ECDSA signature
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::Signature;
    ///
    /// let data = [0u8; 64]; // In practice, this would be a real signature
    /// let signature = Signature::ecdsa_from_data(data);
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn ecdsa_from_data(data: [u8; ECDSA_SIGNATURE_SIZE]) -> Self {
        Self::ECDSA(data)
    }

    /// Creates an ECDSA signature from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the signature data
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature or an error if the data is not
    /// exactly 64 bytes in length.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::Signature;
    ///
    /// let data = vec![0u8; 64]; // In practice, this would be a real signature
    /// let signature = Signature::ecdsa_from_data_ref(&data).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn ecdsa_from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ECDSA_SIGNATURE_SIZE {
            return Err(Error::invalid_size(
                "ECDSA signature",
                ECDSA_SIGNATURE_SIZE,
                data.len(),
            ));
        }
        let mut arr = [0u8; ECDSA_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::ecdsa_from_data(arr))
    }

    /// Creates an Ed25519 signature from a 64-byte array.
    ///
    /// # Arguments
    ///
    /// * `data` - The 64-byte signature data
    ///
    /// # Returns
    ///
    /// A new Ed25519 signature
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::Signature;
    ///
    /// let data = [0u8; 64]; // In practice, this would be a real signature
    /// let signature = Signature::ed25519_from_data(data);
    /// ```
    pub fn ed25519_from_data(data: [u8; ED25519_SIGNATURE_SIZE]) -> Self {
        Self::Ed25519(data)
    }

    /// Creates an Ed25519 signature from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the signature data
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature or an error if the data is not
    /// exactly 64 bytes in length.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::Signature;
    ///
    /// let data = vec![0u8; 64]; // In practice, this would be a real signature
    /// let signature = Signature::ed25519_from_data_ref(&data).unwrap();
    /// ```
    pub fn ed25519_from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ED25519_SIGNATURE_SIZE {
            return Err(Error::invalid_size(
                "Ed25519 signature",
                ED25519_SIGNATURE_SIZE,
                data.len(),
            ));
        }
        let mut arr = [0u8; ED25519_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::Ed25519(arr))
    }

    /// Creates an SSH signature from an `SshSig` object.
    ///
    /// # Arguments
    ///
    /// * `sig` - The SSH signature object
    ///
    /// # Returns
    ///
    /// A new SSH signature
    #[cfg(feature = "ssh")]
    pub fn from_ssh(sig: SshSig) -> Self {
        Self::SSH(sig)
    }

    /// Returns the Schnorr signature data if this is a Schnorr signature.
    ///
    /// # Returns
    ///
    /// Some reference to the 64-byte signature data if this is a Schnorr
    /// signature, or None if it's a different signature type.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// use bc_components::{SignatureScheme, Signer};
    ///
    /// // Create a Schnorr signature
    /// let (private_key, _) = SignatureScheme::Schnorr.keypair();
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    ///
    /// // We can access the Schnorr signature data
    /// assert!(signature.to_schnorr().is_some());
    ///
    /// // Create an ECDSA signature
    /// let (ecdsa_key, _) = SignatureScheme::Ecdsa.keypair();
    /// let ecdsa_sig = ecdsa_key.sign(&message).unwrap();
    ///
    /// // This will return None since it's not a Schnorr signature
    /// assert!(ecdsa_sig.to_schnorr().is_none());
    /// # }
    /// ```
    #[cfg(feature = "secp256k1")]
    pub fn to_schnorr(&self) -> Option<&[u8; SCHNORR_SIGNATURE_SIZE]> {
        match self {
            Self::Schnorr(sig) => Some(sig),
            _ => None,
        }
    }

    /// Returns the ECDSA signature data if this is an ECDSA signature.
    ///
    /// # Returns
    ///
    /// Some reference to the 64-byte signature data if this is an ECDSA
    /// signature, or None if it's a different signature type.
    #[cfg(feature = "secp256k1")]
    pub fn to_ecdsa(&self) -> Option<&[u8; ECDSA_SIGNATURE_SIZE]> {
        match self {
            Self::ECDSA(sig) => Some(sig),
            _ => None,
        }
    }

    /// Returns the SSH signature if this is an SSH signature.
    ///
    /// # Returns
    ///
    /// Some reference to the SSH signature if this is an SSH signature,
    /// or None if it's a different signature type.
    #[cfg(feature = "ssh")]
    pub fn to_ssh(&self) -> Option<&SshSig> {
        match self {
            Self::SSH(sig) => Some(sig),
            _ => None,
        }
    }

    /// Determines the signature scheme used to create this signature.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature scheme, or an error if the
    /// signature scheme cannot be determined (e.g., for unsupported SSH
    /// algorithms).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # // Requires secp256k1 feature (enabled by default)
    /// use bc_components::{SignatureScheme, Signer};
    ///
    /// // Create a signature with ECDSA
    /// let (private_key, _) = SignatureScheme::Ecdsa.keypair();
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    ///
    /// // Get the signature scheme
    /// let scheme = signature.scheme().unwrap();
    /// assert_eq!(scheme, SignatureScheme::Ecdsa);
    /// ```
    pub fn scheme(&self) -> Result<SignatureScheme> {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr(_) => Ok(SignatureScheme::Schnorr),
            #[cfg(feature = "secp256k1")]
            Self::ECDSA(_) => Ok(SignatureScheme::Ecdsa),
            Self::Ed25519(_) => Ok(SignatureScheme::Ed25519),
            #[cfg(feature = "ssh")]
            Self::SSH(sig) => match sig.algorithm() {
                ssh_key::Algorithm::Dsa => Ok(SignatureScheme::SshDsa),
                ssh_key::Algorithm::Ecdsa { curve } => match curve {
                    ssh_key::EcdsaCurve::NistP256 => {
                        Ok(SignatureScheme::SshEcdsaP256)
                    }
                    ssh_key::EcdsaCurve::NistP384 => {
                        Ok(SignatureScheme::SshEcdsaP384)
                    }
                    _ => Err(Error::ssh("Unsupported SSH ECDSA curve")),
                },
                ssh_key::Algorithm::Ed25519 => Ok(SignatureScheme::SshEd25519),
                _ => Err(Error::ssh("Unsupported SSH signature algorithm")),
            },
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA(sig) => match sig.level() {
                crate::MLDSA::MLDSA44 => Ok(SignatureScheme::MLDSA44),
                crate::MLDSA::MLDSA65 => Ok(SignatureScheme::MLDSA65),
                crate::MLDSA::MLDSA87 => Ok(SignatureScheme::MLDSA87),
            },
        }
    }
}

/// Debug implementation for Signature
impl std::fmt::Debug for Signature {
    /// Formats the signature for display.
    ///
    /// For binary signatures (Schnorr, ECDSA, Ed25519), displays the
    /// hex-encoded signature data. For SSH and ML-DSA signatures, displays
    /// the signature object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "secp256k1")]
            Signature::Schnorr(data) => f
                .debug_struct("Schnorr")
                .field("data", &hex::encode(data))
                .finish(),
            #[cfg(feature = "secp256k1")]
            Signature::ECDSA(data) => f
                .debug_struct("ECDSA")
                .field("data", &hex::encode(data))
                .finish(),
            Signature::Ed25519(data) => f
                .debug_struct("Ed25519")
                .field("data", &hex::encode(data))
                .finish(),
            #[cfg(feature = "ssh")]
            Signature::SSH(sig) => {
                f.debug_struct("SSH").field("sig", sig).finish()
            }
            #[cfg(feature = "pqcrypto")]
            Signature::MLDSA(sig) => {
                f.debug_struct("MLDSA").field("sig", sig).finish()
            }
        }
    }
}

/// Implementation of AsRef for Signature
impl AsRef<Signature> for Signature {
    /// Returns a reference to self.
    fn as_ref(&self) -> &Signature {
        self
    }
}

/// Implementation of the CBORTagged trait for Signature
impl CBORTagged for Signature {
    /// Returns the CBOR tags used for this type.
    ///
    /// For Signature, the tag is 40020.
    fn cbor_tags() -> Vec<dcbor::Tag> {
        tags_for_values(&[tags::TAG_SIGNATURE])
    }
}

/// Conversion from Signature to CBOR
impl From<Signature> for CBOR {
    /// Converts a Signature to a tagged CBOR value.
    fn from(value: Signature) -> Self {
        value.tagged_cbor()
    }
}

/// Implementation of the CBORTaggedEncodable trait for Signature
impl CBORTaggedEncodable for Signature {
    /// Converts the Signature to an untagged CBOR value.
    ///
    /// The CBOR encoding depends on the signature type:
    ///
    /// - Schnorr: A byte string containing the 64-byte signature
    /// - ECDSA: An array containing the discriminator 1 and the 64-byte
    ///   signature
    /// - Ed25519: An array containing the discriminator 2 and the 64-byte
    ///   signature
    /// - SSH: A tagged text string containing the PEM-encoded signature
    /// - ML-DSA: Delegates to the MLDSASignature implementation
    fn untagged_cbor(&self) -> CBOR {
        match self {
            #[cfg(feature = "secp256k1")]
            Signature::Schnorr(data) => CBOR::to_byte_string(data),
            #[cfg(feature = "secp256k1")]
            Signature::ECDSA(data) => {
                vec![(1).into(), CBOR::to_byte_string(data)].into()
            }
            Signature::Ed25519(data) => {
                vec![(2).into(), CBOR::to_byte_string(data)].into()
            }
            #[cfg(feature = "ssh")]
            Signature::SSH(sig) => {
                let pem = sig.to_pem(LineEnding::LF).unwrap();
                CBOR::to_tagged_value(tags::TAG_SSH_TEXT_SIGNATURE, pem)
            }
            #[cfg(feature = "pqcrypto")]
            Signature::MLDSA(sig) => sig.clone().into(),
        }
    }
}

/// TryFrom implementation for converting CBOR to Signature
impl TryFrom<CBOR> for Signature {
    type Error = dcbor::Error;

    /// Tries to convert a CBOR value to a Signature.
    ///
    /// This is a convenience method that calls from_tagged_cbor.
    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implementation of the CBORTaggedDecodable trait for Signature
impl CBORTaggedDecodable for Signature {
    /// Creates a Signature from an untagged CBOR value.
    ///
    /// # Arguments
    ///
    /// * `cbor` - The CBOR value to decode
    ///
    /// # Returns
    ///
    /// A Result containing the decoded Signature or an error if decoding fails.
    ///
    /// # Format
    ///
    /// The CBOR value must be one of:
    /// - A byte string (interpreted as a Schnorr signature)
    /// - An array of length 2, where the first element is 1 (ECDSA) or 2
    ///   (Ed25519) and the second element is a byte string containing the
    ///   signature data
    /// - A tagged value with a tag for MLDSA or SSH signatures
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        match cbor.clone().into_case() {
            CBORCase::ByteString(bytes) => {
                #[cfg(feature = "secp256k1")]
                {
                    Ok(Self::schnorr_from_data_ref(bytes)?)
                }
                #[cfg(not(feature = "secp256k1"))]
                {
                    let _ = bytes;
                    Err("Schnorr signature not available without secp256k1 feature".into())
                }
            }
            CBORCase::Array(mut elements) => {
                if elements.len() == 2 {
                    let mut drain = elements.drain(0..);
                    let ele_0 = drain.next().unwrap().into_case();
                    let ele_1 = drain.next().unwrap().into_case();
                    match ele_0 {
                        #[cfg(feature = "secp256k1")]
                        CBORCase::ByteString(data) => {
                            return Ok(Self::schnorr_from_data_ref(data)?);
                        }
                        #[cfg(feature = "secp256k1")]
                        CBORCase::Unsigned(1) => {
                            if let CBORCase::ByteString(data) = ele_1 {
                                return Ok(Self::ecdsa_from_data_ref(data)?);
                            }
                        }
                        CBORCase::Unsigned(2) => {
                            if let CBORCase::ByteString(data) = ele_1 {
                                return Ok(Self::ed25519_from_data_ref(data)?);
                            }
                        }
                        _ => (),
                    }
                }
                Err("Invalid signature format".into())
            }
            #[cfg_attr(not(feature = "ssh"), allow(unused_variables))]
            CBORCase::Tagged(tag, item) => match tag.value() {
                #[cfg(feature = "pqcrypto")]
                tags::TAG_MLDSA_SIGNATURE => {
                    let sig = MLDSASignature::try_from(cbor)?;
                    Ok(Self::MLDSA(sig))
                }
                #[cfg(feature = "ssh")]
                tags::TAG_SSH_TEXT_SIGNATURE => {
                    let string = item.try_into_text()?;
                    let pem = SshSig::from_pem(string)
                        .map_err(|_| "Invalid PEM format")?;
                    Ok(Self::SSH(pem))
                }
                _ => Err("Invalid signature format".into()),
            },
            _ => Err("Invalid signature format".into()),
        }
    }
}
