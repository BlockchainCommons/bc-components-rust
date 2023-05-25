use std::{rc::Rc, borrow::Cow};

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORDecodable, CBORError, CBORCodable, CBORTaggedEncodable, CBORTaggedDecodable, CBORTaggedCodable};

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
        if self.aad.is_empty() {
            vec![self.ciphertext.cbor(), self.nonce.cbor(), self.auth.cbor()].cbor()
        } else {
            vec![self.ciphertext.cbor(), self.nonce.cbor(), self.auth.cbor(), self.aad.cbor()].cbor()
        }
    }
}

impl CBORDecodable for EncryptedMessage {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORCodable for EncryptedMessage { }

impl CBORTaggedEncodable for EncryptedMessage {
    fn untagged_cbor(&self) -> CBOR {
        todo!()
    }
}

impl CBORTaggedDecodable for EncryptedMessage {
    fn from_untagged_cbor(_cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        todo!()
    }
}

impl CBORTaggedCodable for EncryptedMessage { }

impl UREncodable for EncryptedMessage { }

impl URDecodable for EncryptedMessage { }

impl URCodable for EncryptedMessage { }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth([u8; Self::AUTH_LENGTH]);

impl Auth {
    pub const AUTH_LENGTH: usize = 16;

    pub fn from_data(data: [u8; Self::AUTH_LENGTH]) -> Self {
        Self(data)
    }

    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::AUTH_LENGTH {
            return None;
        }
        let mut arr = [0u8; Self::AUTH_LENGTH];
        arr.copy_from_slice(data.as_ref());
        Some(Self::from_data(arr))
    }

    pub fn data(&self) -> &[u8] {
        &self.0
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
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = dcbor::Bytes::from_cbor(cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(&data).ok_or(CBORError::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}
