use std::borrow::Cow;
use bc_ur::prelude::*;
use crate::{ Nonce, Digest, DigestProvider, tags, AuthenticationTag };
use anyhow::{ bail, Result, Error };

/// A secure encrypted message.
///
/// Implemented using the IETF ChaCha20-Poly1305 encryption.
///
/// <https://datatracker.ietf.org/doc/html/rfc8439>
///
/// To facilitate decoding, it is recommended that the plaintext of an `EncryptedMessage` be
/// tagged CBOR.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedMessage {
    ciphertext: Vec<u8>,
    aad: Vec<u8>, // Additional authenticated data (AAD) per RFC8439
    nonce: Nonce,
    auth: AuthenticationTag,
}

impl EncryptedMessage {
    /// Restores an EncryptedMessage from its CBOR representation.
    ///
    /// This is a low-level function that is not normally needed.
    pub fn new(
        ciphertext: impl Into<Vec<u8>>,
        aad: impl Into<Vec<u8>>,
        nonce: Nonce,
        auth: AuthenticationTag
    ) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            aad: aad.into(),
            nonce,
            auth,
        }
    }

    /// Returns a reference to the ciphertext data.
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }

    /// Returns a reference to the additional authenticated data (AAD).
    pub fn aad(&self) -> &Vec<u8> {
        &self.aad
    }

    /// Returns a reference to the nonce value used for encryption.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns a reference to the authentication tag value used for encryption.
    pub fn authentication_tag(&self) -> &AuthenticationTag {
        &self.auth
    }

    /// Returns an optional `Digest` instance if the AAD data can be parsed as CBOR.
    pub fn opt_digest(&self) -> Option<Digest> {
        CBOR::try_from_data(self.aad())
            .ok()
            .and_then(|data| Digest::try_from(data).ok())
    }

    /// Returns `true` if the AAD data can be parsed as CBOR.
    pub fn has_digest(&self) -> bool {
        self.opt_digest().is_some()
    }
}

impl std::fmt::Debug for EncryptedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMessage")
            .field("ciphertext", &hex::encode(&self.ciphertext))
            .field("aad", &hex::encode(&self.aad))
            .field("nonce", &self.nonce)
            .field("auth", &self.auth)
            .finish()
    }
}

impl AsRef<EncryptedMessage> for EncryptedMessage {
    fn as_ref(&self) -> &EncryptedMessage {
        self
    }
}

impl DigestProvider for EncryptedMessage {
    fn digest(&self) -> Cow<'_, Digest> {
        let a = self.opt_digest().unwrap();
        Cow::Owned(a)
    }
}

impl CBORTagged for EncryptedMessage {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_ENCRYPTED])
    }
}

impl From<EncryptedMessage> for CBOR {
    fn from(value: EncryptedMessage) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for EncryptedMessage {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedEncodable for EncryptedMessage {
    fn untagged_cbor(&self) -> CBOR {
        let mut a = vec![
            CBOR::to_byte_string(&self.ciphertext),
            CBOR::to_byte_string(self.nonce.data()),
            CBOR::to_byte_string(self.auth.data())
        ];

        if !self.aad.is_empty() {
            a.push(CBOR::to_byte_string(&self.aad));
        }

        a.into()
    }
}

impl CBORTaggedDecodable for EncryptedMessage {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() < 3 {
                    bail!("EncryptedMessage must have at least 3 elements");
                }
                let ciphertext = CBOR::try_into_byte_string(elements[0].clone())?;
                let nonce_data = CBOR::try_into_byte_string(elements[1].clone())?;
                let nonce = Nonce::from_data_ref(nonce_data)?;
                let auth_data = CBOR::try_into_byte_string(elements[2].clone())?;
                let auth = AuthenticationTag::from_data_ref(auth_data)?;
                let aad = if elements.len() > 3 {
                    CBOR::try_into_byte_string(elements[3].clone())?
                } else {
                    Vec::new()
                };
                Ok(Self::new(ciphertext, aad, nonce, auth))
            }
            _ => bail!("EncryptedMessage must be an array"),
        }
    }
}

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
    fn test_rfc_test_vector() -> Result<(), Box<dyn std::error::Error>> {
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
    fn test_random_key_and_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let key = SymmetricKey::new();
        let nonce = Nonce::new();
        let encrypted_message = key.encrypt(PLAINTEXT, Some(&AAD), Some(nonce));
        let decrypted_plaintext = key.decrypt(&encrypted_message)?;
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_empty_data() -> Result<(), Box<dyn std::error::Error>> {
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
    fn test_cbor() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted_message = encrypted_message();
        let cbor = encrypted_message.to_cbor();
        let decoded = cbor.try_into()?;
        assert_eq!(encrypted_message, decoded);
        Ok(())
    }

    #[test]
    fn test_ur() -> Result<(), Box<dyn std::error::Error>> {
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
