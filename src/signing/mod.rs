//! Digital signatures for various cryptographic schemes.
//!
//! This module provides a unified interface for creating and verifying digital signatures
//! using different cryptographic algorithms, including:
//!
//! - **Elliptic Curve Schemes**: ECDSA and Schnorr signatures using the secp256k1 curve
//! - **Edwards Curve Schemes**: Ed25519 signatures
//! - **Post-Quantum Schemes**: ML-DSA (Module Lattice-based Digital Signature Algorithm)
//! - **SSH Schemes**: Various SSH signature algorithms
//!
//! The key types include:
//!
//! - [`SigningPrivateKey`] - Private keys for creating signatures
//! - [`SigningPublicKey`] - Public keys for verifying signatures
//! - [`Signature`] - The digital signatures themselves
//!
//! All types share a common interface through the [`Signer`] and [`Verifier`] traits,
//! and can be serialized to and from CBOR with appropriate tags.
//!
//! # Examples
//!
//! Creating and verifying a signature:
//!
//! ```
//! use bc_components::{SignatureScheme, Signer, Verifier};
//!
//! // Create a key pair using the Schnorr signature scheme
//! let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
//!
//! // Sign a message
//! let message = b"Hello, world!";
//! let signature = private_key.sign(&message).unwrap();
//!
//! // Verify the signature
//! assert!(public_key.verify(&signature, &message));
//!
//! // Verification should fail for a different message
//! assert!(!public_key.verify(&signature, &b"Different message"));
//! ```
//!
//! Different signature schemes:
//!
//! ```
//! use bc_components::{SignatureScheme, Signer};
//!
//! // Create key pairs for different signature schemes
//! let (schnorr_key, _) = SignatureScheme::Schnorr.keypair();
//! let (ecdsa_key, _) = SignatureScheme::Ecdsa.keypair();
//! let (ed25519_key, _) = SignatureScheme::Ed25519.keypair();
//! let (mldsa_key, _) = SignatureScheme::MLDSA65.keypair();
//!
//! // Sign a message with each key
//! let message = b"Hello, world!";
//! let schnorr_sig = schnorr_key.sign(&message).unwrap();
//! let ecdsa_sig = ecdsa_key.sign(&message).unwrap();
//! let ed25519_sig = ed25519_key.sign(&message).unwrap();
//! let mldsa_sig = mldsa_key.sign(&message).unwrap();
//! ```

mod signing_private_key;
pub use signing_private_key::{SigningOptions, SigningPrivateKey};

mod signing_public_key;
pub use signing_public_key::SigningPublicKey;

mod signature;
pub use signature::Signature;

mod signer;
pub use signer::{Signer, Verifier};

mod signature_scheme;
pub use signature_scheme::SignatureScheme;

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use crate::{
        ECPrivateKey, Ed25519PrivateKey, MLDSASignature, Signature, Signer, SigningOptions,
        SigningPrivateKey, Verifier, MLDSA,
    };
    use bc_rand::make_fake_random_number_generator;
    use dcbor::prelude::*;
    use hex_literal::hex;
    use indoc::indoc;
    use ssh_key::HashAlg;

    use super::SignatureScheme;

    const ECDSA_SIGNING_PRIVATE_KEY: SigningPrivateKey =
        SigningPrivateKey::new_ecdsa(ECPrivateKey::from_data(hex!(
            "322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36"
        )));
    const SCHNORR_SIGNING_PRIVATE_KEY: SigningPrivateKey =
        SigningPrivateKey::new_schnorr(ECPrivateKey::from_data(hex!(
            "322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36"
        )));

    const ED25519_SIGNING_PRIVATE_KEY: SigningPrivateKey =
        SigningPrivateKey::new_ed25519(Ed25519PrivateKey::from_data(hex!(
            "322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36"
        )));
    const MESSAGE: &dyn AsRef<[u8]> = b"Wolf McNally";

    #[test]
    fn test_schnorr_signing() {
        let public_key = SCHNORR_SIGNING_PRIVATE_KEY.public_key().unwrap();
        let signature = SCHNORR_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();

        assert!(public_key.verify(&signature, MESSAGE));
        assert!(!public_key.verify(&signature, b"Wolf Mcnally"));

        let another_signature = SCHNORR_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();
        assert_ne!(signature, another_signature);
        assert!(public_key.verify(&another_signature, MESSAGE));
    }

    #[test]
    fn test_schnorr_cbor() {
        let rng = Rc::new(RefCell::new(make_fake_random_number_generator()));
        let options = SigningOptions::Schnorr { rng };
        let signature = SCHNORR_SIGNING_PRIVATE_KEY
            .sign_with_options(MESSAGE, Some(options))
            .unwrap();
        let signature_cbor: CBOR = signature.clone().into();
        let tagged_cbor_data = signature_cbor.to_cbor_data();
        let expected = indoc! {r#"
        40020(
            h'9d113392074dd52dfb7f309afb3698a1993cd14d32bc27c00070407092c9ec8c096643b5b1b535bb5277c44f256441ac660cd600739aa910b150d4f94757cf95'
        )
        "#}.trim();
        assert_eq!(
            CBOR::try_from_data(&tagged_cbor_data).unwrap().diagnostic(),
            expected
        );
        let received_signature = Signature::from_tagged_cbor_data(&tagged_cbor_data).unwrap();
        assert_eq!(signature, received_signature);
    }

    #[test]
    fn test_ecdsa_signing() {
        let public_key = ECDSA_SIGNING_PRIVATE_KEY.public_key().unwrap();
        let signature = ECDSA_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();

        assert!(public_key.verify(&signature, MESSAGE));
        assert!(!public_key.verify(&signature, b"Wolf Mcnally"));

        let another_signature = ECDSA_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();
        assert_eq!(signature, another_signature);
        assert!(public_key.verify(&another_signature, MESSAGE));
    }

    #[test]
    fn test_ecdsa_cbor() {
        let signature = ECDSA_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();
        let signature_cbor: CBOR = signature.clone().into();
        let tagged_cbor_data = signature_cbor.to_cbor_data();
        let expected = indoc! {
        r#"
        40020(
            [
                1,
                h'1458d0f3d97e25109b38fd965782b43213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fba4dc355cd89b47213e855cf6d23'
            ]
        )
        "#}.trim();
        let cbor = CBOR::try_from_data(&tagged_cbor_data).unwrap();
        assert_eq!(cbor.diagnostic(), expected);
        let received_signature = Signature::from_tagged_cbor_data(&tagged_cbor_data).unwrap();
        assert_eq!(signature, received_signature);
    }

    #[test]
    fn test_ed25519_signing() {
        let public_key = ED25519_SIGNING_PRIVATE_KEY.public_key().unwrap();
        let signature = ED25519_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();

        assert!(public_key.verify(&signature, MESSAGE));
        assert!(!public_key.verify(&signature, b"Wolf Mcnally"));

        let another_signature = ED25519_SIGNING_PRIVATE_KEY.sign(MESSAGE).unwrap();
        assert_eq!(signature, another_signature);
        assert!(public_key.verify(&another_signature, MESSAGE));
    }

    #[test]
    fn test_mldsa_signing() {
        let (private_key, public_key) = MLDSA::MLDSA65.keypair();
        let signature = private_key.sign(MESSAGE);

        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key.verify(&signature, b"Wolf Mcnally").unwrap());

        let another_signature = private_key.sign(MESSAGE);
        assert_ne!(signature, another_signature);
    }

    #[test]
    fn test_mldsa_cbor() {
        let (private_key, public_key) = MLDSA::MLDSA65.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        let signature_cbor: CBOR = signature.clone().into();
        let tagged_cbor_data = signature_cbor.to_cbor_data();
        let received_signature = MLDSASignature::from_tagged_cbor_data(tagged_cbor_data).unwrap();
        assert_eq!(signature, received_signature);
    }

    fn test_keypair_signing(scheme: SignatureScheme, options: Option<SigningOptions>) {
        let (private_key, public_key) = scheme.keypair();
        let signature = private_key.sign_with_options(MESSAGE, options).unwrap();
        assert!(public_key.verify(&signature, MESSAGE));
    }

    #[test]
    fn test_schnorr_keypair() {
        test_keypair_signing(SignatureScheme::default(), None);
    }

    #[test]
    fn test_ecdsa_keypair() {
        test_keypair_signing(SignatureScheme::Ecdsa, None);
    }

    #[test]
    fn test_ed25519_keypair() {
        test_keypair_signing(SignatureScheme::Ed25519, None);
    }

    #[test]
    fn test_mldsa44_keypair() {
        test_keypair_signing(SignatureScheme::MLDSA44, None);
    }

    #[test]
    fn test_mldsa65_keypair() {
        test_keypair_signing(SignatureScheme::MLDSA65, None);
    }

    #[test]
    fn test_mldsa87_keypair() {
        test_keypair_signing(SignatureScheme::MLDSA87, None);
    }

    fn signing_options() -> SigningOptions {
        SigningOptions::Ssh { namespace: "ssh".into(), hash_alg: HashAlg::Sha512 }
    }

    #[test]
    fn test_ssh_ed25519_keypair() {
        test_keypair_signing(SignatureScheme::SshEd25519, Some(signing_options()));
    }

    #[test]
    fn test_ssh_dsa_keypair() {
        test_keypair_signing(SignatureScheme::SshDsa, Some(signing_options()));
    }

    #[test]
    fn test_ssh_ecdsa_p256_keypair() {
        test_keypair_signing(SignatureScheme::SshEcdsaP256, Some(signing_options()));
    }

    #[test]
    fn test_ssh_ecdsa_p384_keypair() {
        test_keypair_signing(SignatureScheme::SshEcdsaP384, Some(signing_options()));
    }
}
