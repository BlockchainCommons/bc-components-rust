use std::str::FromStr;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable};
use crate::tags_registry;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct URI(String);

impl URI {
    pub fn new<T>(uri: T) -> Self where T: Into<String> {
        Self(uri.into())
    }
}

impl FromStr for URI {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl CBORTagged for URI {
    const CBOR_TAG: Tag = tags_registry::URI;
}

impl CBOREncodable for URI {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for URI {
    fn untagged_cbor(&self) -> CBOR {
        self.0.cbor()
    }
}

impl CBORDecodable for URI {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for URI {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let uri = String::from_cbor(cbor)?;
        Ok(Self::new(uri))
    }
}

impl std::fmt::Display for URI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Convert from a string to a URI.
impl From<&str> for URI {
    fn from(uri: &str) -> Self {
        Self::new(uri)
    }
}

// Convert from a string to a URI.
impl From<String> for URI {
    fn from(uri: String) -> Self {
        Self::new(uri)
    }
}

// Convert from a URI to a string.
impl From<URI> for String {
    fn from(uri: URI) -> Self {
        uri.0
    }
}

// Convert from a URI to a string.
impl From<&URI> for String {
    fn from(uri: &URI) -> Self {
        uri.0.clone()
    }
}
