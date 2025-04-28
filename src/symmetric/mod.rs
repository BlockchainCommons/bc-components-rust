//! Symmetric cryptography types and operations.
//!
//! This module provides types and operations for symmetric encryption, where the same key is
//! used for both encryption and decryption. It implements the ChaCha20-Poly1305 AEAD
//! (Authenticated Encryption with Associated Data) construction as specified in
//! [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
//!
//! The main components are:
//!
//! - `SymmetricKey`: A 32-byte key used for both encryption and decryption
//! - `AuthenticationTag`: A 16-byte value that verifies message integrity
//! - `EncryptedMessage`: A complete encrypted message containing ciphertext, nonce,
//!   authentication tag, and optional additional authenticated data (AAD)

mod encrypted_message;
pub use encrypted_message::EncryptedMessage;

mod authentication_tag;
pub use authentication_tag::AuthenticationTag;

mod symmetric_key;
pub use symmetric_key::SymmetricKey;

mod encrypted_key;
pub use encrypted_key::{ EncryptedKey, DerivationParams, HashType, KeyDerivationMethod };

#[cfg(test)]
mod test {
    use bc_ur::{ UREncodable, URDecodable };
    use dcbor::prelude::*;
    use hex_literal::hex;
    use indoc::indoc;

    use crate::{ SymmetricKey, Nonce, EncryptedMessage, AuthenticationTag };

    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const AAD: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
    const KEY: SymmetricKey = SymmetricKey::from_data(
        hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    );
    const NONCE: Nonce = Nonce::from_data(hex!("070000004041424344454647"));
    const CIPHERTEXT: [u8; 114] = hex!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    );
    const AUTH: AuthenticationTag = AuthenticationTag::from_data(
        hex!("1ae10b594f09e26a7e902ecbd0600691")
    );

    fn encrypted_message() -> EncryptedMessage {
        KEY.encrypt(PLAINTEXT, Some(&AAD), Some(NONCE))
    }

    #[test]
    fn test_rfc_test_vector() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let encrypted_message = encrypted_message();
        assert_eq!(encrypted_message.ciphertext(), &CIPHERTEXT);
        assert_eq!(encrypted_message.aad(), &AAD);
        assert_eq!(encrypted_message.nonce(), &NONCE);
        assert_eq!(encrypted_message.authentication_tag(), &AUTH);

        let decrypted_plaintext = KEY.decrypt(&encrypted_message)?;
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_random_key_and_nonce() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = SymmetricKey::new();
        let nonce = Nonce::new();
        let encrypted_message = key.encrypt(PLAINTEXT, Some(&AAD), Some(nonce));
        let decrypted_plaintext = key.decrypt(&encrypted_message)?;
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_empty_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = SymmetricKey::new();
        let encrypted_message = key.encrypt(vec![], None::<Vec<u8>>, None::<Nonce>);
        let decrypted_plaintext = key.decrypt(&encrypted_message)?;
        assert_eq!(&[] as &[u8], decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_cbor_data() {
        crate::register_tags();
        let cbor: CBOR = encrypted_message().into();
        #[rustfmt::skip]
        let expected = indoc!(r#"
            40002(   / encrypted /
                [
                    h'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116',
                    h'070000004041424344454647',
                    h'1ae10b594f09e26a7e902ecbd0600691',
                    h'50515253c0c1c2c3c4c5c6c7'
                ]
            )
        "#).trim();
        assert_eq!(cbor.diagnostic_annotated(), expected);

        #[rustfmt::skip]
        let expected = indoc!(r#"
            d9 9c42                                 # tag(40002) encrypted
                84                                  # array(4)
                    5872                            # bytes(114)
                        d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116
                    4c                              # bytes(12)
                        070000004041424344454647    # "....@ABCDEFG"
                    50                              # bytes(16)
                        1ae10b594f09e26a7e902ecbd0600691
                    4c                              # bytes(12)
                        50515253c0c1c2c3c4c5c6c7
        "#).trim();
        assert_eq!(cbor.hex_annotated(), expected);

        let data = cbor.to_cbor_data();
        let expected = hex!(
            "d99c42845872d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61164c070000004041424344454647501ae10b594f09e26a7e902ecbd06006914c50515253c0c1c2c3c4c5c6c7"
        );
        assert_eq!(data, expected);
    }

    #[test]
    fn test_cbor() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let encrypted_message = encrypted_message();
        let cbor = encrypted_message.to_cbor();
        let decoded = cbor.try_into()?;
        assert_eq!(encrypted_message, decoded);
        Ok(())
    }

    #[test]
    fn test_ur() -> std::result::Result<(), Box<dyn std::error::Error>> {
        crate::register_tags();
        let encrypted_message = encrypted_message();
        let ur = encrypted_message.ur();
        let expected_ur =
            "ur:encrypted/lrhdjptecylgeeiemnhnuykglnperfguwskbsaoxpmwegydtjtayzeptvoreosenwyidtbfsrnoxhylkptiobglfzszointnmojplucyjsuebknnambddtahtbonrpkbsnfrenmoutrylbdpktlulkmkaxplvldeascwhdzsqddkvezstbkpmwgolplalufdehtsrffhwkuewtmngrknntvwkotdihlntoswgrhscmgsataeaeaefzfpfwfxfyfefgflgdcyvybdhkgwasvoimkbmhdmsbtihnammegsgdgygmgurtsesasrssskswstcfnbpdct";
        assert_eq!(ur.to_string(), expected_ur);
        let decoded = EncryptedMessage::from_ur(ur).unwrap();
        assert_eq!(encrypted_message, decoded);
        Ok(())
    }
}
