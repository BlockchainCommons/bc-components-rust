use std::rc::Rc;

use anyhow::{ bail, Error, Result };
use dcbor::prelude::*;

/// The HMAC authentication tag produced by the encryption process.
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
    pub fn data(&self) -> &[u8; Self::AUTHENTICATION_TAG_SIZE] {
        self.into()
    }
}

impl AsRef<AuthenticationTag> for AuthenticationTag {
    fn as_ref(&self) -> &AuthenticationTag {
        self
    }
}

impl std::fmt::Debug for AuthenticationTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AuthenticationTag").field(&hex::encode(self.data())).finish()
    }
}

impl From<Rc<AuthenticationTag>> for AuthenticationTag {
    fn from(value: Rc<AuthenticationTag>) -> Self {
        (*value).clone()
    }
}

impl<'a> From<&'a AuthenticationTag> for &'a [u8; AuthenticationTag::AUTHENTICATION_TAG_SIZE] {
    fn from(value: &'a AuthenticationTag) -> Self {
        &value.0
    }
}

impl From<&[u8]> for AuthenticationTag {
    fn from(data: &[u8]) -> Self {
        Self::from_data_ref(data).unwrap()
    }
}

impl From<[u8; Self::AUTHENTICATION_TAG_SIZE]> for AuthenticationTag {
    fn from(data: [u8; Self::AUTHENTICATION_TAG_SIZE]) -> Self {
        Self::from_data(data)
    }
}

impl From<Vec<u8>> for AuthenticationTag {
    fn from(data: Vec<u8>) -> Self {
        Self::from_data_ref(data).unwrap()
    }
}

impl From<AuthenticationTag> for CBOR {
    fn from(value: AuthenticationTag) -> Self {
        CBOR::to_byte_string(value.data())
    }
}

impl TryFrom<CBOR> for AuthenticationTag {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Self::from_data_ref(data)
    }
}
