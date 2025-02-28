use bc_rand::RandomNumberGenerator;
use ssh_key::Algorithm;

use crate::{ECPrivateKey, Ed25519PrivateKey, PrivateKeyBase};

use super::{SigningPrivateKey, SigningPublicKey};

use anyhow::{bail, Result};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum SignatureScheme {
    #[default]
    Schnorr,
    Ecdsa,
    Ed25519,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    SshEd25519,

    // Disabled due to tests not working correctly for undiagnosed reasons.
    // SshRsaSha256,
    // SshRsaSha512,
    SshDsa,
    SshEcdsaP256,
    SshEcdsaP384,
    // Disabled due to a bug in the ssh-key crate.
    // See: https://github.com/RustCrypto/SSH/issues/232

    // SSH-ECDSA NIST P-521
    // SshEcdsaP521,
}

impl SignatureScheme {
    pub fn keypair(&self) -> (SigningPrivateKey, SigningPublicKey) {
        self.keypair_opt("")
    }

    pub fn keypair_opt(&self, comment: impl Into<String>) -> (SigningPrivateKey, SigningPublicKey) {
        match self {
            Self::Schnorr => {
                let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new());
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            Self::Ecdsa => {
                let private_key = SigningPrivateKey::new_ecdsa(ECPrivateKey::new());
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            Self::Ed25519 => {
                let private_key = SigningPrivateKey::new_ed25519(Ed25519PrivateKey::new());
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            Self::MLDSA44 => {
                let (private_key, public_key) = crate::MLDSA::MLDSA44.keypair();
                let private_key = SigningPrivateKey::MLDSA(private_key);
                let public_key = SigningPublicKey::MLDSA(public_key);
                (private_key, public_key)
            }
            Self::MLDSA65 => {
                let (private_key, public_key) = crate::MLDSA::MLDSA65.keypair();
                let private_key = SigningPrivateKey::MLDSA(private_key);
                let public_key = SigningPublicKey::MLDSA(public_key);
                (private_key, public_key)
            }
            Self::MLDSA87 => {
                let (private_key, public_key) = crate::MLDSA::MLDSA87.keypair();
                let private_key = SigningPrivateKey::MLDSA(private_key);
                let public_key = SigningPublicKey::MLDSA(public_key);
                (private_key, public_key)
            }
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
            Self::SshDsa => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Dsa, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            Self::SshEcdsaP256 => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
            Self::SshEcdsaP384 => {
                let private_key_base = PrivateKeyBase::new();
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP384 },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
        }
    }

    pub fn keypair_using(
        &self,
        rng: &mut impl RandomNumberGenerator,
        comment: impl Into<String>,
    ) -> Result<(SigningPrivateKey, SigningPublicKey)> {
        match self {
            Self::Schnorr => {
                let private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new_using(rng));
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            Self::Ecdsa => {
                let private_key = SigningPrivateKey::new_ecdsa(ECPrivateKey::new_using(rng));
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            Self::Ed25519 => {
                let private_key = SigningPrivateKey::new_ed25519(Ed25519PrivateKey::new_using(rng));
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            Self::SshEd25519 => {
                let private_key_base = PrivateKeyBase::new_using(rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Ed25519, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            Self::SshDsa => {
                let private_key_base = PrivateKeyBase::new_using(rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(Algorithm::Dsa, comment)
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            Self::SshEcdsaP256 => {
                let private_key_base = PrivateKeyBase::new_using(rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            Self::SshEcdsaP384 => {
                let private_key_base = PrivateKeyBase::new_using(rng);
                let private_key = private_key_base
                    .ssh_signing_private_key(
                        Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP384 },
                        comment,
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                Ok((private_key, public_key))
            }
            _ => bail!("Deterministic keypair generation not supported for this signature scheme"),
        }
    }
}
