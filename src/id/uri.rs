use std::str::FromStr;

use anyhow::{Error, Result, bail};
use dcbor::prelude::*;
use url::Url;

use crate::tags;

/// A Uniform Resource Identifier (URI).
///
/// A URI is a string of characters that unambiguously identifies a particular
/// resource. This implementation validates URIs using the `url` crate to ensure
/// conformance to RFC 3986.
///
/// URIs are commonly used for:
/// - Web addresses (URLs like "<https://example.com>")
/// - Resource identifiers in various protocols
/// - Namespace identifiers
/// - References to resources in distributed systems
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct URI(String);

impl URI {
    /// Creates a new `URI` from a string.
    ///
    /// No validation is performed on the string.
    pub fn new(uri: impl Into<String>) -> Result<Self> {
        let uri = uri.into();
        if Url::parse(&uri).is_ok() {
            Ok(Self(uri))
        } else {
            bail!("Invalid URI")
        }
    }
}

/// Implements string parsing to create a URI.
impl FromStr for URI {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::new(s) }
}

/// Implements `AsRef<str>` to allow URI to be treated as a string slice.
impl AsRef<str> for URI {
    fn as_ref(&self) -> &str { &self.0 }
}

/// Implements `AsRef<String>` to allow URI to be treated as a String reference.
impl AsRef<String> for URI {
    fn as_ref(&self) -> &String { &self.0 }
}

/// Implements `AsRef<URI>` to allow URI to reference itself.
impl AsRef<URI> for URI {
    fn as_ref(&self) -> &URI { self }
}

/// Implements CBORTagged trait to provide CBOR tag information.
impl CBORTagged for URI {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_URI]) }
}

/// Implements conversion from URI to CBOR for serialization.
impl From<URI> for CBOR {
    fn from(value: URI) -> Self { value.tagged_cbor() }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
impl CBORTaggedEncodable for URI {
    fn untagged_cbor(&self) -> CBOR { self.0.clone().into() }
}

/// Implements `TryFrom<CBOR>` for URI to support conversion from CBOR data.
impl TryFrom<CBOR> for URI {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for URI {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let uri: String = cbor.try_into()?;
        Ok(Self::new(uri)?)
    }
}

/// Implements Display for URI to format as a string.
impl std::fmt::Display for URI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Implements conversion from string slice to URI with validation.
impl TryFrom<&str> for URI {
    type Error = Error;

    fn try_from(uri: &str) -> Result<Self, Self::Error> { Self::new(uri) }
}

/// Implements conversion from String to URI with validation.
impl TryFrom<String> for URI {
    type Error = Error;

    fn try_from(uri: String) -> Result<Self, Self::Error> {
        Self::try_from(uri.as_str())
    }
}

/// Implements conversion from URI to String.
impl From<URI> for String {
    fn from(uri: URI) -> Self { uri.0 }
}

/// Implements conversion from URI reference to String.
impl From<&URI> for String {
    fn from(uri: &URI) -> Self { uri.0.clone() }
}
