use std::{rc::Rc, borrow::Cow};

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORDecodable, CBORCodable, CBORTaggedEncodable, CBORTaggedDecodable, CBORTaggedCodable, Bytes};

use crate::{Nonce, Digest, DigestProvider, tags_registry};

/// A secure encrypted message.
///
/// Implemented using the IETF ChaCha20-Poly1305 encryption.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
///
/// To facilitate decoding, it is recommended that the plaintext of an `EncryptedMessage` be
/// tagged CBOR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedMessage {
    ciphertext: Vec<u8>,
    aad: Vec<u8>, // Additional authenticated data (AAD) per RFC8439
    nonce: Nonce,
    auth: Auth,
}

impl EncryptedMessage {
    pub fn new(ciphertext: Vec<u8>, aad: Vec<u8>, nonce: Nonce, auth: Auth) -> Self {
        Self {
            ciphertext,
            aad,
            nonce,
            auth,
        }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    pub fn has_digest(&self) -> bool {
        todo!();
    }

    pub fn digest_ref_opt(&self) -> Option<&Digest> {
        todo!();
    }
}

impl DigestProvider for EncryptedMessage {
    fn digest(&self) -> Cow<Digest> {
        todo!();
    }
}

impl CBORTagged for EncryptedMessage {
    const CBOR_TAG: Tag = tags_registry::ENCRYPTED;
}

impl CBOREncodable for EncryptedMessage {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORDecodable for EncryptedMessage {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORCodable for EncryptedMessage { }

impl CBORTaggedEncodable for EncryptedMessage {
    fn untagged_cbor(&self) -> CBOR {
        let mut a = vec![
            Bytes::from_data(&self.ciphertext).cbor(),
            Bytes::from_data(self.nonce.data()).cbor(),
            Bytes::from_data(self.auth.data()).cbor()
        ];

        if !self.aad.is_empty() {
            a.push(Bytes::from_data(&self.aad).cbor());
        }

        a.cbor()
    }
}

impl CBORTaggedDecodable for EncryptedMessage {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        match cbor {
            CBOR::Array(elements) => {
                if elements.len() < 3 {
                    return Err(dcbor::Error::InvalidFormat);
                }
                let ciphertext = Bytes::from_cbor(&elements[0])?.data().to_vec();
                let nonce: Nonce = Nonce::from_untagged_cbor(&elements[1])?.into();
                let auth = Auth::from_cbor(&elements[2])?.into();
                let aad = if elements.len() > 3 {
                    Bytes::from_cbor(&elements[3])?.data().to_vec()
                } else {
                    Vec::<u8>::new()
                };
                Ok(Rc::new(Self::new(ciphertext, aad, nonce, auth)))
            },
            _ => Err(dcbor::Error::InvalidFormat),
        }
    }
}

impl CBORTaggedCodable for EncryptedMessage { }

impl UREncodable for EncryptedMessage { }

impl URDecodable for EncryptedMessage { }

impl URCodable for EncryptedMessage { }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth([u8; Self::AUTH_SIZE]);

impl Auth {
    pub const AUTH_SIZE: usize = 16;

    pub const fn from_data(data: [u8; Self::AUTH_SIZE]) -> Self {
        Self(data)
    }

    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::AUTH_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::AUTH_SIZE];
        arr.copy_from_slice(data.as_ref());
        Some(Self::from_data(arr))
    }

    pub fn data(&self) -> &[u8; Self::AUTH_SIZE] {
        &self.0
    }
}

impl From<Rc<Auth>> for Auth {
    fn from(value: Rc<Auth>) -> Self {
        (*value).clone()
    }
}

impl AsRef<[u8]> for Auth {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Auth {
    fn from(data: &[u8]) -> Self {
        Self::from_data_ref(&data).unwrap()
    }
}

impl From<Vec<u8>> for Auth {
    fn from(data: Vec<u8>) -> Self {
        Self::from_data_ref(&data).unwrap()
    }
}

impl CBOREncodable for Auth {
    fn cbor(&self) -> CBOR {
        dcbor::Bytes::from_data(self.data()).cbor()
    }
}

impl CBORDecodable for Auth {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = dcbor::Bytes::from_cbor(cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

#[cfg(test)]
mod test {
    use bc_ur::{UREncodable, URDecodable};
    use dcbor::{CBOREncodable, CBORDecodable};
    use hex_literal::hex;
    use indoc::indoc;

    use crate::{SymmetricKey, Nonce, EncryptedMessage, Auth, with_known_tags};

    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const AAD: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
    const KEY: SymmetricKey = SymmetricKey::from_data(hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
    const NONCE: Nonce = Nonce::from_data(hex!("070000004041424344454647"));
    const CIPHERTEXT: [u8; 114] = hex!("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
    const AUTH: Auth = Auth::from_data(hex!("1ae10b594f09e26a7e902ecbd0600691"));

    fn encrypted_message() -> EncryptedMessage {
        KEY.encrypt_with_nonce(PLAINTEXT, AAD, NONCE)
    }

    #[test]
    fn test_rfc_test_vector() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted_message = encrypted_message();
        assert_eq!(encrypted_message.ciphertext(), &CIPHERTEXT);
        assert_eq!(encrypted_message.aad(), &AAD);
        assert_eq!(encrypted_message.nonce(), &NONCE);
        assert_eq!(encrypted_message.auth(), &AUTH);

        let decrypted_plaintext = KEY.decrypt(&encrypted_message)?;
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_random_key_and_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let key = SymmetricKey::new();
        let nonce = Nonce::new();
        let encrypted_message = key.encrypt_with_nonce(PLAINTEXT, AAD, nonce);
        let decrypted_plaintext = key.decrypt(&encrypted_message)?;
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_empty_data() -> Result<(), Box<dyn std::error::Error>> {
        let key = SymmetricKey::new();
        let encrypted_message = key.encrypt([], []);
        let decrypted_plaintext = key.decrypt(&encrypted_message)?;
        assert_eq!(&[] as &[u8], decrypted_plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_cbor_data() {
        with_known_tags!(|known_tags| {
            assert_eq!(encrypted_message().cbor().diagnostic_opt(true, Some(known_tags)),
            indoc!(r#"
            205(   ; encrypted
               [
                  h'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116',
                  h'070000004041424344454647',
                  h'1ae10b594f09e26a7e902ecbd0600691',
                  h'50515253c0c1c2c3c4c5c6c7'
               ]
            )
            "#).trim());

            assert_eq!(encrypted_message().cbor().hex_opt(true, Some(known_tags)),
            indoc!(r#"
            d8 cd                                    # tag(205)   ; encrypted
               84                                    # array(4)
                  5872                               # bytes(114)
                     d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116
                  4c                                 # bytes(12)
                     070000004041424344454647        # "....@ABCDEFG"
                  50                                 # bytes(16)
                     1ae10b594f09e26a7e902ecbd0600691
                  4c                                 # bytes(12)
                     50515253c0c1c2c3c4c5c6c7
            "#).trim());
        });

        let data = encrypted_message().cbor_data();
        let expected = hex!("d8cd845872d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61164c070000004041424344454647501ae10b594f09e26a7e902ecbd06006914c50515253c0c1c2c3c4c5c6c7");
        assert_eq!(data, expected);
    }

    #[test]
    fn test_cbor() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted_message = encrypted_message();
        let cbor = encrypted_message.cbor();
        let decoded = EncryptedMessage::from_cbor(&cbor)?;
        assert_eq!(encrypted_message, *decoded);
        Ok(())
    }

    #[test]
    fn test_ur() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted_message = encrypted_message();
        let ur = encrypted_message.ur();
        let expected_ur = "ur:encrypted/lrhdjptecylgeeiemnhnuykglnperfguwskbsaoxpmwegydtjtayzeptvoreosenwyidtbfsrnoxhylkptiobglfzszointnmojplucyjsuebknnambddtahtbonrpkbsnfrenmoutrylbdpktlulkmkaxplvldeascwhdzsqddkvezstbkpmwgolplalufdehtsrffhwkuewtmngrknntvwkotdihlntoswgrhscmgsataeaeaefzfpfwfxfyfefgflgdcyvybdhkgwasvoimkbmhdmsbtihnammegsgdgygmgurtsesasrssskswstcfnbpdct";
        assert_eq!(ur.to_string(), expected_ur);
        let decoded = EncryptedMessage::from_ur(&ur).unwrap();
        assert_eq!(encrypted_message, *decoded);
        Ok(())
    }
}
