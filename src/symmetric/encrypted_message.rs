use std::borrow::Cow;
use bc_ur::prelude::*;
use crate::{ Nonce, Digest, DigestProvider, tags, AuthenticationTag };

/// A secure encrypted message using IETF ChaCha20-Poly1305 authenticated encryption.
///
/// `EncryptedMessage` represents data that has been encrypted using a symmetric key with the
/// ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) construction as
/// specified in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
///
/// An `EncryptedMessage` contains:
/// - `ciphertext`: The encrypted data (same length as the original plaintext)
/// - `aad`: Additional Authenticated Data that is not encrypted but is authenticated (optional)
/// - `nonce`: A 12-byte number used once for this specific encryption operation
/// - `auth`: A 16-byte authentication tag that verifies the integrity of the message
///
/// The `aad` field is often used to include the `Digest` of the plaintext, which allows
/// verification of the plaintext after decryption and preserves the unique identity of
/// the data when used with structures like Gordian Envelope.
///
/// To facilitate decoding, it is recommended that the plaintext of an `EncryptedMessage` be
/// tagged CBOR.
///
/// CDDL:
/// ```cddl
/// EncryptedMessage =
///     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, ? aad: bstr ]) ; TAG_ENCRYPTED
/// ```
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
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        nonce: Nonce,
        auth: AuthenticationTag
    ) -> Self {
        Self {
            ciphertext: ciphertext.as_ref().to_vec(),
            aad: aad.as_ref().to_vec(),
            nonce,
            auth,
        }
    }

    /// Returns a reference to the ciphertext data.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns a reference to the additional authenticated data (AAD).
    pub fn aad(&self) -> &[u8] {
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

/// Implements Debug formatting to display the message contents in a structured format.
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

/// Implements `AsRef<EncryptedMessage>` to allow self-reference.
impl AsRef<EncryptedMessage> for EncryptedMessage {
    fn as_ref(&self) -> &EncryptedMessage {
        self
    }
}

/// Implements DigestProvider to provide the digest stored in the AAD field.
impl DigestProvider for EncryptedMessage {
    fn digest(&self) -> Cow<'_, Digest> {
        let a = self.opt_digest().unwrap();
        Cow::Owned(a)
    }
}

/// Implements CBORTagged to provide the CBOR tag for the EncryptedMessage.
impl CBORTagged for EncryptedMessage {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_ENCRYPTED])
    }
}

/// Implements conversion from EncryptedMessage to CBOR for serialization.
impl From<EncryptedMessage> for CBOR {
    fn from(value: EncryptedMessage) -> Self {
        value.tagged_cbor()
    }
}

/// Implements `TryFrom<CBOR>` for EncryptedMessage to support conversion from CBOR data.
impl TryFrom<CBOR> for EncryptedMessage {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
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

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for EncryptedMessage {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        match cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() < 3 {
                    return Err("EncryptedMessage must have at least 3 elements".into());
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
            _ => return Err("EncryptedMessage must be an array".into()),
        }
    }
}
