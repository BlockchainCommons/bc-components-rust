mod digest;
pub use digest::Digest;

mod cid;
pub use cid::CID;

mod digest_provider;
pub use digest_provider::DigestProvider;

mod compressed;
pub use compressed::Compressed;

mod nonce;
pub use nonce::Nonce;

mod symmetric_key;
pub use symmetric_key::SymmetricKey;

mod encrypted_message;
pub use encrypted_message::{EncryptedMessage, Auth};

mod salt;
pub use salt::Salt;

mod uri;
pub use uri::URI;

mod uuid;
pub use uuid::UUID;

mod agreement_public_key;
pub use agreement_public_key::AgreementPublicKey;

mod agreement_private_key;
pub use agreement_private_key::AgreementPrivateKey;

mod signature;
pub use signature::Signature;

mod signing_private_key;
pub use signing_private_key::SigningPrivateKey;

mod signing_public_key;
pub use signing_public_key::SigningPublicKey;

mod ec_key;
pub use ec_key::*;

pub mod tags_registry;
pub use tags_registry::KNOWN_TAGS;

#[cfg(test)]
mod tests {
    use crate::{AgreementPrivateKey, AgreementPublicKey, tags_registry, SigningPrivateKey, SigningPublicKey};
    use bc_crypto::{make_fake_random_number_generator, ecdsa_new_private_key_using, ecdsa_public_key_from_private_key, ecdsa_sign, ecdsa_verify, schnorr_public_key_from_private_key, RandomNumberGenerator, schnorr_sign_using, schnorr_verify};
    use bc_ur::{UREncodable, URDecodable};
    use hex_literal::hex;

    #[test]
    fn tags() {
        assert_eq!(tags_registry::LEAF.value(), 24);
        assert_eq!(tags_registry::LEAF.name().as_ref().unwrap(), Some("leaf").unwrap());
    }

    #[test]
    fn test_agreement_keys() {
        let mut rng = make_fake_random_number_generator();
        let private_key = AgreementPrivateKey::new_using(&mut rng);
        let private_key_ur = private_key.ur_string();
        assert_eq!(private_key_ur, "ur:agreement-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct");
        assert_eq!(AgreementPrivateKey::from_ur_string(private_key_ur).unwrap().as_ref(), &private_key);

        let public_key = private_key.public_key();
        let public_key_ur = public_key.ur_string();
        assert_eq!(public_key_ur, "ur:agreement-public-key/hdcxwnryknkbbymnoxhswmptgydsotwswsghfmrkksfxntbzjyrnuornkildchgswtdahehpwkrl");
        assert_eq!(AgreementPublicKey::from_ur_string(public_key_ur).unwrap().as_ref(), &public_key);

        let derived_private_key = AgreementPrivateKey::derive_from_key_material("password".as_bytes());
        assert_eq!(derived_private_key.ur_string(), "ur:agreement-private-key/hdcxkgcfkomeeyiemywkftvabnrdolmttlrnfhjnguvaiehlrldmdpemgyjlatdthsnecytdoxat");
    }

    #[test]
    fn test_agreement() {
        let mut rng = make_fake_random_number_generator();
        let alice_private_key = AgreementPrivateKey::new_using(&mut rng);
        let alice_public_key = alice_private_key.public_key();

        let bob_private_key = AgreementPrivateKey::new_using(&mut rng);
        let bob_public_key = bob_private_key.public_key();

        let alice_shared_key = alice_private_key.shared_key_with(&bob_public_key);
        let bob_shared_key = bob_private_key.shared_key_with(&alice_public_key);
        assert_eq!(alice_shared_key, bob_shared_key);
    }

    #[test]
    fn test_signing_keys() {
        let mut rng = make_fake_random_number_generator();
        let private_key = SigningPrivateKey::new_using(&mut rng);
        let private_key_ur = private_key.ur_string();
        assert_eq!(private_key_ur, "ur:signing-private-key/hdcxkbrehkrkrsjztodseytknecfgewmgdmwfsvdvysbpmghuozsprknfwkpnehydlweynwkrtct");
        assert_eq!(SigningPrivateKey::from_ur_string(private_key_ur).unwrap().as_ref(), &private_key);

        let ecdsa_public_key = private_key.ecdsa_public_key();
        let ecdsa_public_key_ur = ecdsa_public_key.ur_string();
        assert_eq!(ecdsa_public_key_ur, "ur:signing-public-key/lfadhdclaojsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjedkwftboe");
        assert_eq!(SigningPublicKey::from_ur_string(ecdsa_public_key_ur).unwrap().as_ref(), &ecdsa_public_key);

        let schnorr_public_key = private_key.schnorr_public_key();
        let schnorr_public_key_ur = schnorr_public_key.ur_string();
        assert_eq!(schnorr_public_key_ur, "ur:signing-public-key/hdcxjsrhdnidbgosndmobzwntdglzonnidmwoyrnuomdrpsptkcskerhfljssgaoidjewyjymhcp");
        assert_eq!(SigningPublicKey::from_ur_string(schnorr_public_key_ur).unwrap().as_ref(), &schnorr_public_key);

        let derived_private_key = SigningPrivateKey::derive_from_key_material("password".as_bytes());
        assert_eq!(derived_private_key.ur_string(), "ur:signing-private-key/hdcxahsfgobtpkkpahmnhsfmhnjnmkmkzeuraonneshkbysseyjkoeayrlvtvsmndicwkkvattfs");
    }

    #[test]
    fn test_signing() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ecdsa_public_key = ecdsa_public_key_from_private_key(&private_key);
        let ecdsa_signature = ecdsa_sign(&private_key, MESSAGE);
        assert_eq!(ecdsa_signature, hex!("e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb"));
        assert!(ecdsa_verify(&ecdsa_public_key, &ecdsa_signature, MESSAGE));

        let schnorr_public_key = schnorr_public_key_from_private_key(&private_key);
        let tag = rng.random_data(16);
        let schnorr_signature = schnorr_sign_using(&private_key, MESSAGE, &tag, &mut rng);
        assert_eq!(schnorr_signature, hex!("15d7396ed2862dfa813679a0a0377d8d55310ff693ef913bc9cddd48aa93e0542e416b52e0572ec20a2b47db1904c9e7632f1229d8b16af09fb4f6e3f8feefa0"));
        assert!(schnorr_verify(&schnorr_public_key, &schnorr_signature, MESSAGE, tag));
    }
}
