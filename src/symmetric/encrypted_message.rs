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
