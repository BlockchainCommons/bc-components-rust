#![doc(html_root_url = "https://docs.rs/bc-components/0.21.0")]
#![warn(rust_2018_idioms)]

//! # Introduction
//!
//! A collection of useful primitives for cryptography, semantic graphs, and
//! cryptocurrency, primarily for use in higher-level [Blockchain
//! Commons](https://blockchaincommons.com) projects like [Gordian
//! Envelope](https://crates.io/crates/bc-envelope). All the types are
//! [CBOR](https://cbor.io) serializable, and a number of them can also be
//! serialized to and from [URs](https://crates.io/crates/bc-ur).
//!
//! Also includes a library of CBOR tags and UR types for use with these types.
//!
//! # Getting Started
//!
//! ```toml
//! [dependencies]
//! bc-components = "0.21.0"
//! ```

mod digest;
pub use digest::Digest;

mod id;
pub use id::{ARID, URI, UUID, XID, XIDProvider};

mod digest_provider;
pub use digest_provider::DigestProvider;

mod compressed;
pub use compressed::Compressed;

mod nonce;
pub use nonce::Nonce;

mod symmetric;
pub use symmetric::{AuthenticationTag, EncryptedMessage, SymmetricKey};

mod encrypted_key;
pub use encrypted_key::*;

mod salt;
pub use salt::Salt;

mod x25519;
pub use x25519::{X25519PrivateKey, X25519PublicKey};

mod ed25519;
pub use ed25519::{Ed25519PrivateKey, Ed25519PublicKey};

mod seed;
pub use seed::Seed;

mod signing;
pub use signing::{
    Signature, SignatureScheme, Signer, SigningOptions, SigningPrivateKey, SigningPublicKey,
    Verifier,
};

mod encrypter;
pub use encrypter::{Decrypter, Encrypter};

mod ec_key;
pub use ec_key::*;

mod reference;
/// CBOR Tags used or defined by this crate.
pub use bc_tags as tags;
pub use reference::*;
pub mod tags_registry;
pub use tags_registry::{register_tags, register_tags_in};

mod private_key_data_provider;
pub use private_key_data_provider::PrivateKeyDataProvider;

mod private_key_base;
pub use private_key_base::PrivateKeyBase;

mod private_keys;
pub use private_keys::{PrivateKeys, PrivateKeysProvider};

mod public_keys;
pub use public_keys::{PublicKeys, PublicKeysProvider};

mod mldsa;
pub use mldsa::{MLDSA, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature};

mod mlkem;
pub use mlkem::{MLKEM, MLKEMCiphertext, MLKEMPrivateKey, MLKEMPublicKey};

mod encapsulation;
pub use encapsulation::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme,
    SealedMessage,
};

mod sskr_mod;
pub use sskr::SSKRError;
pub use sskr_mod::{
    SSKRGroupSpec, SSKRSecret, SSKRShare, SSKRSpec, sskr_combine, sskr_generate,
    sskr_generate_using,
};

mod hkdf_rng;
pub use hkdf_rng::HKDFRng;

mod keypair;
pub use keypair::{keypair, keypair_opt, keypair_opt_using, keypair_using};

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use bc_crypto::{
        ecdsa_new_private_key_using, ecdsa_public_key_from_private_key, ecdsa_sign, ecdsa_verify,
        schnorr_public_key_from_private_key, schnorr_sign_using, schnorr_verify,
    };
    use bc_rand::make_fake_random_number_generator;
    use bc_ur::{URDecodable, UREncodable};
    use hex_literal::hex;
    use indoc::indoc;
    use ssh_key::{
        Algorithm as SSHAlgorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey as SSHPrivateKey,
        PublicKey as SSHPublicKey,
    };

    use crate::{
        ECPrivateKey, PrivateKeyBase, Signature, Signer, SigningOptions, SigningPrivateKey,
        SigningPublicKey, Verifier, X25519PrivateKey, X25519PublicKey,
    };

    #[test]
    fn test_x25519_keys() {
        crate::register_tags();
        let mut rng = make_fake_random_number_generator();
        let private_key = X25519PrivateKey::new_using(&mut rng);
        let private_key_ur = private_key.ur_string();
        assert_eq!(
            private_key_ur,
            "ur:agreement-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct"
        );
        assert_eq!(
            X25519PrivateKey::from_ur_string(private_key_ur).unwrap(),
            private_key
        );

        let public_key = private_key.public_key();
        let public_key_ur = public_key.ur_string();
        assert_eq!(
            public_key_ur,
            "ur:agreement-public-key/hdcxwnryknkbbymnoxhswmptgydsotwswsghfmrkksfxntbzjyrnuornkildchgswtdahehpwkrl"
        );
        assert_eq!(
            X25519PublicKey::from_ur_string(public_key_ur).unwrap(),
            public_key
        );

        let derived_private_key = X25519PrivateKey::derive_from_key_material("password".as_bytes());
        assert_eq!(
            derived_private_key.ur_string(),
            "ur:agreement-private-key/hdcxkgcfkomeeyiemywkftvabnrdolmttlrnfhjnguvaiehlrldmdpemgyjlatdthsnecytdoxat"
        );
    }

    #[test]
    fn test_agreement() {
        let mut rng = make_fake_random_number_generator();
        let alice_private_key = X25519PrivateKey::new_using(&mut rng);
        let alice_public_key = alice_private_key.public_key();

        let bob_private_key = X25519PrivateKey::new_using(&mut rng);
        let bob_public_key = bob_private_key.public_key();

        let alice_shared_key = alice_private_key.shared_key_with(&bob_public_key);
        let bob_shared_key = bob_private_key.shared_key_with(&alice_public_key);
        assert_eq!(alice_shared_key, bob_shared_key);
    }

    #[test]
    fn test_ecdsa_signing_keys() {
        crate::register_tags();
        let mut rng = make_fake_random_number_generator();
        let schnorr_private_key = SigningPrivateKey::new_schnorr(ECPrivateKey::new_using(&mut rng));
        let schnorr_private_key_ur = schnorr_private_key.ur_string();
        assert_eq!(
            schnorr_private_key_ur,
            "ur:signing-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct"
        );
        assert_eq!(
            SigningPrivateKey::from_ur_string(schnorr_private_key_ur).unwrap(),
            schnorr_private_key
        );

        let ecdsa_private_key = SigningPrivateKey::new_ecdsa(ECPrivateKey::new_using(&mut rng));
        let ecdsa_public_key = ecdsa_private_key.public_key().unwrap();
        let ecdsa_public_key_ur = ecdsa_public_key.ur_string();
        assert_eq!(
            ecdsa_public_key_ur,
            "ur:signing-public-key/lfadhdclaxbzutckgevlpkmdfnuoemlnvsgllokicfdekesswnfdtibkylrskomwgubaahyntaktbksbdt"
        );
        assert_eq!(
            SigningPublicKey::from_ur_string(ecdsa_public_key_ur).unwrap(),
            ecdsa_public_key
        );

        let schnorr_public_key = schnorr_private_key.public_key().unwrap();
        let schnorr_public_key_ur = schnorr_public_key.ur_string();
        assert_eq!(
            schnorr_public_key_ur,
            "ur:signing-public-key/hdcxjsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjewyjymhcp"
        );
        assert_eq!(
            SigningPublicKey::from_ur_string(schnorr_public_key_ur).unwrap(),
            schnorr_public_key
        );

        let derived_private_key = SigningPrivateKey::new_schnorr(
            ECPrivateKey::derive_from_key_material("password".as_bytes()),
        );
        assert_eq!(
            derived_private_key.ur_string(),
            "ur:signing-private-key/hdcxahsfgobtpkkpahmnhsfmhnjnmkmkzeuraonneshkbysseyjkoeayrlvtvsmndicwkkvattfs"
        );
    }

    fn test_ssh_signing(
        algorithm: SSHAlgorithm,
        expected_private_key: Option<&str>,
        expected_public_key: Option<&str>,
    ) {
        const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");
        let private_key_base = PrivateKeyBase::from_data(SEED);

        let private_key: SigningPrivateKey = private_key_base
            .ssh_signing_private_key(algorithm, "Key comment.")
            .unwrap();
        let ssh_private_key: &SSHPrivateKey = private_key.to_ssh().unwrap();
        let ssh_private_key_string = ssh_private_key.to_openssh(LineEnding::default()).unwrap();

        let public_key: SigningPublicKey = private_key.public_key().unwrap();
        let ssh_public_key: &SSHPublicKey = public_key.to_ssh().unwrap();
        let ssh_public_key_string = ssh_public_key.to_openssh().unwrap();

        if let Some(expected_private_key) = expected_private_key {
            assert_eq!(ssh_private_key_string.deref(), expected_private_key);
        } else {
            println!("{}", *ssh_private_key_string);
        }

        if let Some(expected_public_key) = expected_public_key {
            assert_eq!(ssh_public_key_string.deref(), expected_public_key);
        } else {
            println!("{}", ssh_public_key_string);
        }

        const MESSAGE: &dyn AsRef<[u8]> = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let options = SigningOptions::Ssh {
            namespace: "test".to_string(),
            hash_alg: HashAlg::Sha256,
        };
        let signature: Signature = private_key
            .sign_with_options(MESSAGE, Some(options))
            .unwrap();
        assert!(public_key.verify(&signature, MESSAGE));
    }

    #[test]
    fn test_ssh_dsa_signing() {
        #[rustfmt::skip]
        let expected_private_key = Some(indoc! {r#"
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsgAAAAdzc2gtZH
            NzAAAAgQCWG4f7r8FAMT/IL11w9OfM/ZduIQ8vEq1Ub+uMdyJS8wS/jXL5OB2/dPnXCNSt
            L4vjSqpDzMs+Dtd5wJy6baSQ3zGEbYv71mkIRJB/AtSVmd8FZe5AEjLFvHxYMSlO0jpi1Y
            /1nLM7vLQu4QByDCLhYYjPxgrZKXB3cLxtjvly5wAAABUA4fIZLivnDVcg9PXzwcb5m07H
            9k0AAACBAJK5Vm6t1Sg7n+C63wrNgDA6LTNyGzxqRVM2unI16jisCOzuC98Dgs+IbAkLhT
            qWSY+nI+U9HBHc7sr+KKdWCzR76NLK5eSilXvtt8g+LfHIXvCjD4Q2puowtjDoXSEQAJYd
            c1gtef21KZ2eoKoyAwzQIehCbvLpwYbxnhap5usVAAAAgGCrsbfReaDZo1Cw4/dFlJWBDP
            sMGeG04/2hCThNmU+zLiKCwsEg0X6onOTMTonCXve3fVb5lNjIU92iTmt5QkmOj2hjsbgo
            q/0sa0lALHp7UcK/W4IdU4Abtc4m0SUflgJcds1nsy2rKUNEtAfRa/WwtDResWOa4T7L+3
            FEUdavAAAB6F0RJ3hdESd4AAAAB3NzaC1kc3MAAACBAJYbh/uvwUAxP8gvXXD058z9l24h
            Dy8SrVRv64x3IlLzBL+Ncvk4Hb90+dcI1K0vi+NKqkPMyz4O13nAnLptpJDfMYRti/vWaQ
            hEkH8C1JWZ3wVl7kASMsW8fFgxKU7SOmLVj/Wcszu8tC7hAHIMIuFhiM/GCtkpcHdwvG2O
            +XLnAAAAFQDh8hkuK+cNVyD09fPBxvmbTsf2TQAAAIEAkrlWbq3VKDuf4LrfCs2AMDotM3
            IbPGpFUza6cjXqOKwI7O4L3wOCz4hsCQuFOpZJj6cj5T0cEdzuyv4op1YLNHvo0srl5KKV
            e+23yD4t8che8KMPhDam6jC2MOhdIRAAlh1zWC15/bUpnZ6gqjIDDNAh6EJu8unBhvGeFq
            nm6xUAAACAYKuxt9F5oNmjULDj90WUlYEM+wwZ4bTj/aEJOE2ZT7MuIoLCwSDRfqic5MxO
            icJe97d9VvmU2MhT3aJOa3lCSY6PaGOxuCir/SxrSUAsentRwr9bgh1TgBu1zibRJR+WAl
            x2zWezLaspQ0S0B9Fr9bC0NF6xY5rhPsv7cURR1q8AAAAVANWljfuxQcmJ/T7wSmAUXmXo
            6ZI0AAAADEtleSBjb21tZW50LgECAwQF
            -----END OPENSSH PRIVATE KEY-----
        "#});
        let expected_public_key = Some(
            "ssh-dss AAAAB3NzaC1kc3MAAACBAJYbh/uvwUAxP8gvXXD058z9l24hDy8SrVRv64x3IlLzBL+Ncvk4Hb90+dcI1K0vi+NKqkPMyz4O13nAnLptpJDfMYRti/vWaQhEkH8C1JWZ3wVl7kASMsW8fFgxKU7SOmLVj/Wcszu8tC7hAHIMIuFhiM/GCtkpcHdwvG2O+XLnAAAAFQDh8hkuK+cNVyD09fPBxvmbTsf2TQAAAIEAkrlWbq3VKDuf4LrfCs2AMDotM3IbPGpFUza6cjXqOKwI7O4L3wOCz4hsCQuFOpZJj6cj5T0cEdzuyv4op1YLNHvo0srl5KKVe+23yD4t8che8KMPhDam6jC2MOhdIRAAlh1zWC15/bUpnZ6gqjIDDNAh6EJu8unBhvGeFqnm6xUAAACAYKuxt9F5oNmjULDj90WUlYEM+wwZ4bTj/aEJOE2ZT7MuIoLCwSDRfqic5MxOicJe97d9VvmU2MhT3aJOa3lCSY6PaGOxuCir/SxrSUAsentRwr9bgh1TgBu1zibRJR+WAlx2zWezLaspQ0S0B9Fr9bC0NF6xY5rhPsv7cURR1q8= Key comment.",
        );
        test_ssh_signing(SSHAlgorithm::Dsa, expected_private_key, expected_public_key);
    }

    #[test]
    #[ignore]
    fn test_ssh_dsa_nistp256_signing() {
        #[rustfmt::skip]
        let expected_private_key = Some(indoc! {r#"
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
            1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTtBE6+WTueAierXl/c/f83JAmoxm0k
            YlGMVMofLOUFeKx3FqUW0VRVljx1wHL03faFhiTPVR9CNG5iZCUqa4eLAAAAqPC+XgXwvl
            4FAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO0ETr5ZO54CJ6te
            X9z9/zckCajGbSRiUYxUyh8s5QV4rHcWpRbRVFWWPHXAcvTd9oWGJM9VH0I0bmJkJSprh4
            sAAAAgAVk1Bq0ILFsF/ADaUq8G5Tow0Xv+Qs8V21gfOBSWQDEAAAAMS2V5IGNvbW1lbnQu
            AQIDBA==
            -----END OPENSSH PRIVATE KEY-----
        "#});
        let expected_public_key = Some(
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO0ETr5ZO54CJ6teX9z9/zckCajGbSRiUYxUyh8s5QV4rHcWpRbRVFWWPHXAcvTd9oWGJM9VH0I0bmJkJSprh4s= Key comment.",
        );
        test_ssh_signing(
            SSHAlgorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
            expected_private_key,
            expected_public_key,
        );
    }

    #[test]
    #[ignore]
    fn test_ssh_dsa_nistp384_signing() {
        #[rustfmt::skip]
        let expected_private_key = Some(indoc! {r#"
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
            1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSdYtV5QyUoBDDJX9gOG3DcJyv4qhjV
            L7ntdIlyOCVCdqMMWa2EUsyxV/PLrrDYGCDUruf83rRNdJwuZ+7oZWm0N6yfLOT4QPQNxv
            LqMJJ1hvw/xBxZVjMsr2gb/ohSG6IAAADYBFI75gRSO+YAAAATZWNkc2Etc2hhMi1uaXN0
            cDM4NAAAAAhuaXN0cDM4NAAAAGEEnWLVeUMlKAQwyV/YDhtw3Ccr+KoY1S+57XSJcjglQn
            ajDFmthFLMsVfzy66w2Bgg1K7n/N60TXScLmfu6GVptDesnyzk+ED0Dcby6jCSdYb8P8Qc
            WVYzLK9oG/6IUhuiAAAAMQCFOcU/ldvVE92+kXn2C/q5+wuGX3Q61YHG3LNn4655GZeL7a
            rH0jbCy0lsAQ5WbsMAAAAMS2V5IGNvbW1lbnQuAQID
            -----END OPENSSH PRIVATE KEY-----
        "#});
        let expected_public_key = Some(
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJ1i1XlDJSgEMMlf2A4bcNwnK/iqGNUvue10iXI4JUJ2owxZrYRSzLFX88uusNgYINSu5/zetE10nC5n7uhlabQ3rJ8s5PhA9A3G8uowknWG/D/EHFlWMyyvaBv+iFIbog== Key comment.",
        );
        test_ssh_signing(
            SSHAlgorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
            expected_private_key,
            expected_public_key,
        );
    }

    // Should succeed but fails part of the time. See next test.
    #[test]
    #[ignore]
    fn test_ssh_dsa_nistp521_signing() {
        #[rustfmt::skip]
        let expected_private_key = Some(indoc! {r#"
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
            1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBD3AAo2UN1WreSuQWtp4DTbfzQ+D2
            LyK9u5ykCfFXd/AMpQbyIyEQGbAiLNyAhGOfLgarJiAv4myKcHSGW2fTxQUB3V09IqubOw
            JdNLaCJbszLQQSqoZlIWrXD51X7FdQFtXYY4GKmVeMKuK+u9Iby6F41nSrYpHlaFzzxr+D
            5n1uq7cAAAEQrIPPE6yDzxMAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
            AAAIUEAQ9wAKNlDdVq3krkFraeA02380Pg9i8ivbucpAnxV3fwDKUG8iMhEBmwIizcgIRj
            ny4GqyYgL+JsinB0hltn08UFAd1dPSKrmzsCXTS2giW7My0EEqqGZSFq1w+dV+xXUBbV2G
            OBiplXjCrivrvSG8uheNZ0q2KR5Whc88a/g+Z9bqu3AAAAQgGDA9XptdyVFY5Svw8XXSJ5
            7lrvc2R/T2CBthF0FgxqlNF5oTdqmrFuEqJ34oxIvhd9sJB/3qBpoJnPVKcuVmGC6gAAAA
            xLZXkgY29tbWVudC4BAgMEBQY=
            -----END OPENSSH PRIVATE KEY-----
        "#});
        let expected_public_key = Some(
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEPcACjZQ3Vat5K5Ba2ngNNt/ND4PYvIr27nKQJ8Vd38AylBvIjIRAZsCIs3ICEY58uBqsmIC/ibIpwdIZbZ9PFBQHdXT0iq5s7Al00toIluzMtBBKqhmUhatcPnVfsV1AW1dhjgYqZV4wq4r670hvLoXjWdKtikeVoXPPGv4PmfW6rtw== Key comment.",
        );
        test_ssh_signing(
            SSHAlgorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
            expected_private_key,
            expected_public_key,
        );
    }

    // Filed as https://github.com/RustCrypto/SSH/issues/232
    #[ignore]
    #[test]
    fn test_dsa_nistp521() {
        let encoded_key = r#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBD3AAo2UN1WreSuQWtp4DTbfzQ+D2
LyK9u5ykCfFXd/AMpQbyIyEQGbAiLNyAhGOfLgarJiAv4myKcHSGW2fTxQUB3V09IqubOw
JdNLaCJbszLQQSqoZlIWrXD51X7FdQFtXYY4GKmVeMKuK+u9Iby6F41nSrYpHlaFzzxr+D
5n1uq7cAAAEQrIPPE6yDzxMAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAQ9wAKNlDdVq3krkFraeA02380Pg9i8ivbucpAnxV3fwDKUG8iMhEBmwIizcgIRj
ny4GqyYgL+JsinB0hltn08UFAd1dPSKrmzsCXTS2giW7My0EEqqGZSFq1w+dV+xXUBbV2G
OBiplXjCrivrvSG8uheNZ0q2KR5Whc88a/g+Z9bqu3AAAAQgGDA9XptdyVFY5Svw8XXSJ5
7lrvc2R/T2CBthF0FgxqlNF5oTdqmrFuEqJ34oxIvhd9sJB/3qBpoJnPVKcuVmGC6gAAAA
xLZXkgY29tbWVudC4BAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
"#;
        let private_key = SSHPrivateKey::from_openssh(encoded_key).unwrap();
        const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const NAMESPACE: &str = "test";
        let signature = private_key
            .sign(NAMESPACE, HashAlg::Sha256, MESSAGE)
            .unwrap();
        let public_key = private_key.public_key();
        public_key.verify(NAMESPACE, MESSAGE, &signature).unwrap();
    }

    #[test]
    fn test_ssh_ed25519_signing() {
        #[rustfmt::skip]
        let expected_private_key = Some(indoc! {r#"
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
            QyNTUxOQAAACBUe4FDGyGIgHf75yVdE4hYl9guj02FdsIadgLC04zObQAAAJA+TyZiPk8m
            YgAAAAtzc2gtZWQyNTUxOQAAACBUe4FDGyGIgHf75yVdE4hYl9guj02FdsIadgLC04zObQ
            AAAECsX3CKi3hm5VrrU26ffa2FB2YrFogg45ucOVbIz4FQo1R7gUMbIYiAd/vnJV0TiFiX
            2C6PTYV2whp2AsLTjM5tAAAADEtleSBjb21tZW50LgE=
            -----END OPENSSH PRIVATE KEY-----
        "#});
        let expected_public_key = Some(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFR7gUMbIYiAd/vnJV0TiFiX2C6PTYV2whp2AsLTjM5t Key comment.",
        );
        test_ssh_signing(
            SSHAlgorithm::Ed25519,
            expected_private_key,
            expected_public_key,
        );
    }

    #[test]
    fn test_ecdsa_signing() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ecdsa_public_key = ecdsa_public_key_from_private_key(&private_key);
        let ecdsa_signature = ecdsa_sign(&private_key, MESSAGE);
        assert_eq!(
            ecdsa_signature,
            hex!(
                "e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb"
            )
        );
        assert!(ecdsa_verify(&ecdsa_public_key, &ecdsa_signature, MESSAGE));

        let schnorr_public_key = schnorr_public_key_from_private_key(&private_key);
        let schnorr_signature = schnorr_sign_using(&private_key, MESSAGE, &mut rng);
        assert_eq!(
            schnorr_signature,
            hex!(
                "df3e33900f0b94e23b6f8685f620ed92705ebfcf885ccb321620acb9927bce1e2218dcfba7cb9c3bba11611446f38774a564f265917899194e82945c8b60a996"
            )
        );
        assert!(schnorr_verify(
            &schnorr_public_key,
            &schnorr_signature,
            MESSAGE
        ));
    }

    #[test]
    fn test_readme_deps() {
        version_sync::assert_markdown_deps_updated!("README.md");
    }

    #[test]
    fn test_html_root_url() {
        version_sync::assert_html_root_url_updated!("src/lib.rs");
    }
}
