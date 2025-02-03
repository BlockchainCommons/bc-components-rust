use ssh_key::Algorithm;

use crate::{ ECPrivateKey, Ed25519PrivateKey, PrivateKeyBase };

use super::{ SigningPrivateKey, SigningPublicKey };

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum SignatureScheme {
    #[default]
    Schnorr,
    Ecdsa,
    Ed25519,
    Dilithium2,
    Dilithium3,
    Dilithium5,
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
            Self::Dilithium2 => {
                let (private_key, public_key) = crate::Dilithium::Dilithium2.keypair();
                let private_key = SigningPrivateKey::Dilithium(private_key);
                let public_key = SigningPublicKey::Dilithium(public_key);
                (private_key, public_key)
            }
            Self::Dilithium3 => {
                let (private_key, public_key) = crate::Dilithium::Dilithium3.keypair();
                let private_key = SigningPrivateKey::Dilithium(private_key);
                let public_key = SigningPublicKey::Dilithium(public_key);
                (private_key, public_key)
            }
            Self::Dilithium5 => {
                let (private_key, public_key) = crate::Dilithium::Dilithium5.keypair();
                let private_key = SigningPrivateKey::Dilithium(private_key);
                let public_key = SigningPublicKey::Dilithium(public_key);
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
                        comment
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
                        comment
                    )
                    .unwrap();
                let public_key = private_key.public_key().unwrap();
                (private_key, public_key)
            }
        }
    }
}
