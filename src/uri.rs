use std::rc::Rc;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes, CBORError};
use crate::tags_registry;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct URI(String);

impl URI {
    pub fn from_str(uri: &str) -> Self {
        Self(uri.to_string())
    }

    pub fn from_string(uri: String) -> Self {
        Self(uri)
    }

    pub fn to_str(&self) -> &str {
        &self.0
    }

    pub fn to_string(&self) -> String {
        self.0.clone()
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
        Bytes::from_data(self.0.as_bytes()).cbor()
    }
}

impl CBORDecodable for URI {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for URI {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = Bytes::from_cbor(cbor)?;
        let uri = String::from_utf8(bytes.data().to_vec()).map_err(|_| CBORError::InvalidFormat)?;
        Ok(Rc::new(Self::from_string(uri)))
    }
}

impl std::fmt::Display for URI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "URI({})", self.0)
    }
}

// Convert from a string to a URI.
impl From<&str> for URI {
    fn from(uri: &str) -> Self {
        Self::from_str(uri)
    }
}

// Convert from a string to a URI.
impl From<String> for URI {
    fn from(uri: String) -> Self {
        Self::from_string(uri)
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
