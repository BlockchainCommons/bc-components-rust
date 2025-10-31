use bc_rand::RandomNumberGenerator;
#[cfg(feature = "ssh")]
use ssh_key::Algorithm;

use super::{SigningPrivateKey, SigningPublicKey};
#[cfg(feature = "secp256k1")]
use crate::ECPrivateKey;
#[cfg(feature = "ed25519")]
use crate::Ed25519PrivateKey;
#[cfg(feature = "ssh")]
use crate::PrivateKeyBase;
#[cfg_attr(not(feature = "pqcrypto"), allow(unused_imports))]
use crate::{Error, Result};

/// Supported digital signature schemes.
///
/// This enum represents the various signature schemes supported in this crate,
/// including elliptic curve schemes (ECDSA, Schnorr), Edwards curve schemes
/// (Ed25519), post-quantum schemes (ML-DSA), and SSH-specific algorithms.
///
/// # Examples
///
/// ```
/// use bc_components::SignatureScheme;
///
/// // Use the default signature scheme (Schnorr)
/// let scheme = SignatureScheme::default();
/// let (private_key, public_key) = scheme.keypair();
/// ```
///
/// ```ignore
/// # use bc_components::SignatureScheme;
/// // Create a key pair using a specific signature scheme
/// let (mldsa_private, mldsa_public) = SignatureScheme::MLDSA65.keypair();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "secp256k1", derive(Default))]
#[cfg_attr(
    all(feature = "ed25519", not(feature = "secp256k1")),
    derive(Default)
)]
pub enum SignatureScheme {
    /// BIP-340 Schnorr signature scheme, used in Bitcoin Taproot (default)
    #[cfg(feature = "secp256k1")]
    #[cfg_attr(feature = "secp256k1", default)]
    Schnorr,

    /// ECDSA signature scheme using the secp256k1 curve
    #[cfg(feature = "secp256k1")]
    Ecdsa,

    /// Ed25519 signature scheme (RFC 8032)
    #[cfg(feature = "ed25519")]
    #[cfg_attr(all(feature = "ed25519", not(feature = "secp256k1")), default)]
    Ed25519,

    /// ML-DSA44 post-quantum signature scheme (NIST level 2)
    #[cfg(feature = "pqcrypto")]
    MLDSA44,

    /// ML-DSA65 post-quantum signature scheme (NIST level 3)
    #[cfg(feature = "pqcrypto")]
    MLDSA65,

    /// ML-DSA87 post-quantum signature scheme (NIST level 5)
    #[cfg(feature = "pqcrypto")]
    MLDSA87,

    /// Ed25519 signature scheme for SSH
    #[cfg(all(
        feature = "ssh",
        any(feature = "secp256k1", feature = "ed25519")
    ))]
    SshEd25519,

    // Disabled due to tests not working correctly for undiagnosed reasons.
    // SshRsaSha256,
    // SshRsaSha512,
    /// DSA signature scheme for SSH
    #[cfg(all(
        feature = "ssh",
        any(feature = "secp256k1", feature = "ed25519")
    ))]
    SshDsa,

    /// ECDSA signature scheme with NIST P-256 curve for SSH
    #[cfg(all(
        feature = "ssh",
        any(feature = "secp256k1", feature = "ed25519")
    ))]
    SshEcdsaP256,

    /// ECDSA signature scheme with NIST P-384 curve for SSH
    #[cfg(all(
        feature = "ssh",
        any(feature = "secp256k1", feature = "ed25519")
    ))]
    SshEcdsaP384,
    // Disabled due to a bug in the ssh-key crate.
    // See: https://github.com/RustCrypto/SSH/issues/232

    // SSH-ECDSA NIST P-521
    // SshEcdsaP521,
}

impl SignatureScheme {
    /// Creates a new key pair for the signature scheme using the system's
    /// secure random number generator.
    ///
    /// This is a convenience method that calls `keypair_opt` with an empty
    /// comment.
    ///
    /// # Returns
    ///
    /// A tuple containing a signing private key and its corresponding public
    /// key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # // Requires secp256k1 feature (enabled by default)
    /// use bc_components::SignatureScheme;
    ///
    /// // Generate a Schnorr key pair
    /// let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
    ///
    /// // Use the default scheme (also Schnorr)
    /// let (default_private, default_public) =
    ///     SignatureScheme::default().keypair();
    /// ```
    pub fn keypair(&self) -> (SigningPrivateKey, SigningPublicKey) {
        self.keypair_opt("")
    }

    /// Creates a new key pair for the signature scheme with an optional
    /// comment.
    ///
    /// The comment is only used for SSH keys and is ignored for other schemes.
    ///
    /// # Arguments
    ///
    /// * `comment` - A string comment to include with SSH keys
    ///
    /// # Returns
    ///
    /// A tuple containing a signing private key and its corresponding public
    /// key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use bc_components::SignatureScheme;
    ///
    /// // Generate an SSH Ed25519 key pair with a comment
    /// let (ssh_private, ssh_public) =
    ///     SignatureScheme::SshEd25519.keypair_opt("user@example.com");
    /// ```
    pub fn keypair_opt(
        &self,
        comment: impl Into<String>,
    ) -> (SigningPrivateKey, SigningPublicKey) {
        #[cfg_attr(not(feature = "ssh"), allow(unused_variables))]
        let comment = comment.into();
        #[allow(unreachable_patterns)]
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr => {
                let private_key =
                    SigningPrivateKey::new_schnorr(ECPrivateKey::new());
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            #[cfg(feature = "secp256k1")]
            Self::Ecdsa => {
                let private_key =
                    SigningPrivateKey::new_ecdsa(ECPrivateKey::new());
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519 => {
                let private_key =
                    SigningPrivateKey::new_ed25519(Ed25519PrivateKey::new());
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA44 => {
                let (private_key, public_key) = crate::MLDSA::MLDSA44.keypair();
                let private_key = SigningPrivateKey::MLDSA(private_key);
                let public_key = SigningPublicKey::MLDSA(public_key);
                (private_key, public_key)
            }
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA65 => {
                let (private_key, public_key) = crate::MLDSA::MLDSA65.keypair();
                let private_key = SigningPrivateKey::MLDSA(private_key);
                let public_key = SigningPublicKey::MLDSA(public_key);
                (private_key, public_key)
            }
            #[cfg(feature = "pqcrypto")]
            Self::MLDSA87 => {
                let (private_key, public_key) = crate::MLDSA::MLDSA87.keypair();
                let private_key = SigningPrivateKey::MLDSA(private_key);
                let public_key = SigningPublicKey::MLDSA(public_key);
                (private_key, public_key)
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshEd25519 => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Ed25519, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            // Self::SshRsaSha256 => {
            //     let private_key_base = PrivateKeyBase::new();
            //     let private_key = private_key_base
            //         .ssh_signing_private_key(
            //             Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            //             comment
            //         )
            //         .unwrap();
            //     let public_key = private_key.public_key().unwrap();
            //     (private_key, public_key)
            // }
            // Self::SshRsaSha512 => {
            //     let private_key_base = PrivateKeyBase::new();
            //     let private_key = private_key_base
            //         .ssh_signing_private_key(
            //             Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
            //             comment
            //         )
            //         .unwrap();
            //     let public_key = private_key.public_key().unwrap();
            //     (private_key, public_key)
            // }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshDsa => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Dsa, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshEcdsaP256 => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa {
                            curve: ssh_key::EcdsaCurve::NistP256,
                        },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshEcdsaP384 => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa {
                            curve: ssh_key::EcdsaCurve::NistP384,
                        },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            #[cfg(not(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "pqcrypto"
            )))]
            _ => unreachable!(),
        }
    }

    /// Creates a key pair for the signature scheme using a provided random
    /// number generator.
    ///
    /// This allows for deterministic key generation when using a seeded RNG.
    /// Note that not all signature schemes support deterministic generation.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator
    /// * `comment` - A string comment to include with SSH keys
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple of signing private key and public key, or
    /// an error if the signature scheme doesn't support deterministic
    /// generation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # // Requires secp256k1 feature (enabled by default)
    /// use bc_components::SignatureScheme;
    /// use bc_rand::SecureRandomNumberGenerator;
    ///
    /// let mut rng = SecureRandomNumberGenerator;
    ///
    /// // Generate an ECDSA key pair with a specific RNG
    /// let result = SignatureScheme::Ecdsa.keypair_using(&mut rng, "");
    /// assert!(result.is_ok());
    /// ```
    pub fn keypair_using(
        &self,
        _rng: &mut impl RandomNumberGenerator,
        comment: impl Into<String>,
    ) -> Result<(SigningPrivateKey, SigningPublicKey)> {
        #[cfg_attr(not(feature = "ssh"), allow(unused_variables))]
        let comment = comment.into();
        #[allow(unreachable_patterns)]
        match self {
            #[cfg(feature = "secp256k1")]
            Self::Schnorr => {
                let private_key = SigningPrivateKey::new_schnorr(
                    ECPrivateKey::new_using(_rng),
                );
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(feature = "secp256k1")]
            Self::Ecdsa => {
                let private_key =
                    SigningPrivateKey::new_ecdsa(ECPrivateKey::new_using(_rng));
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519 => {
                let private_key = SigningPrivateKey::new_ed25519(
                    Ed25519PrivateKey::new_using(_rng),
                );
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshEd25519 => {
                let private_key_base = PrivateKeyBase::new_using(_rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Ed25519, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshDsa => {
                let private_key_base = PrivateKeyBase::new_using(_rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Dsa, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshEcdsaP256 => {
                let private_key_base = PrivateKeyBase::new_using(_rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa {
                            curve: ssh_key::EcdsaCurve::NistP256,
                        },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(all(
                feature = "ssh",
                any(feature = "secp256k1", feature = "ed25519")
            ))]
            Self::SshEcdsaP384 => {
                let private_key_base = PrivateKeyBase::new_using(_rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa {
                            curve: ssh_key::EcdsaCurve::NistP384,
                        },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            #[cfg(feature = "pqcrypto")]
            _ => Err(Error::general(
                "Deterministic keypair generation not supported for this signature scheme",
            )),
            #[cfg(not(any(
                feature = "secp256k1",
                feature = "ed25519",
                feature = "pqcrypto"
            )))]
            _ => unreachable!(),
        }
    }
}
