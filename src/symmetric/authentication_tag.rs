use std::rc::Rc;

use anyhow::{Error, Result, bail};
use dcbor::prelude::*;

/// The authentication tag produced by the encryption process to verify message
/// integrity.
///
/// An `AuthenticationTag` is a 16-byte value generated during ChaCha20-Poly1305
/// authenticated encryption. It serves as a message authentication code (MAC)
/// that verifies both the authenticity and integrity of the encrypted message.
///
/// During decryption, the tag is verified to ensure:
/// - The message has not been tampered with (integrity)
/// - The message was encrypted by someone who possesses the encryption key
///   (authenticity)
///
/// This implementation follows the Poly1305 MAC algorithm as specified in
/// [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticationTag([u8; Self::AUTHENTICATION_TAG_SIZE]);

impl AuthenticationTag {
    pub const AUTHENTICATION_TAG_SIZE: usize = 16;

    /// Restore an `AuthenticationTag` from a fixed-size array of bytes.
    pub const fn from_data(data: [u8; Self::AUTHENTICATION_TAG_SIZE]) -> Self {
        Self(data)
    }

    /// Restore an `AuthenticationTag` from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::AUTHENTICATION_TAG_SIZE {
            bail!("Invalid authentication tag size");
        }
        let mut arr = [0u8; Self::AUTHENTICATION_TAG_SIZE];
        arr.copy_from_slice(data.as_ref());
        Ok(Self::from_data(arr))
    }

    /// Get a reference to the fixed-size array of bytes.
    pub fn data(&self) -> &[u8; Self::AUTHENTICATION_TAG_SIZE] { self.into() }

    /// Get the reference as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }
}

impl AsRef<[u8]> for AuthenticationTag {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements `AsRef<AuthenticationTag>` to allow self-reference.
impl AsRef<AuthenticationTag> for AuthenticationTag {
    fn as_ref(&self) -> &AuthenticationTag { self }
}

/// Implements Debug formatting to display the tag in hexadecimal format.
impl std::fmt::Debug for AuthenticationTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AuthenticationTag")
            .field(&hex::encode(self.data()))
            .finish()
    }
}

/// Implements conversion from a reference-counted AuthenticationTag to an owned
/// AuthenticationTag.
impl From<Rc<AuthenticationTag>> for AuthenticationTag {
    fn from(value: Rc<AuthenticationTag>) -> Self { (*value).clone() }
}

/// Implements conversion from an AuthenticationTag reference to a byte array
/// reference.
impl<'a> From<&'a AuthenticationTag>
    for &'a [u8; AuthenticationTag::AUTHENTICATION_TAG_SIZE]
{
    fn from(value: &'a AuthenticationTag) -> Self { &value.0 }
}

/// Implements conversion from a byte slice to an AuthenticationTag.
impl From<&[u8]> for AuthenticationTag {
    fn from(data: &[u8]) -> Self { Self::from_data_ref(data).unwrap() }
}

/// Implements conversion from a fixed-size byte array to an AuthenticationTag.
impl From<[u8; Self::AUTHENTICATION_TAG_SIZE]> for AuthenticationTag {
    fn from(data: [u8; Self::AUTHENTICATION_TAG_SIZE]) -> Self {
        Self::from_data(data)
    }
}

/// Implements conversion from a byte vector to an AuthenticationTag.
impl From<Vec<u8>> for AuthenticationTag {
    fn from(data: Vec<u8>) -> Self { Self::from_data_ref(data).unwrap() }
}

/// Implements conversion from AuthenticationTag to CBOR for serialization.
impl From<AuthenticationTag> for CBOR {
    fn from(value: AuthenticationTag) -> Self {
        CBOR::to_byte_string(value.data())
    }
}

/// Implements conversion from CBOR to AuthenticationTag for deserialization.
impl TryFrom<CBOR> for AuthenticationTag {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Self::from_data_ref(data)
    }
}
