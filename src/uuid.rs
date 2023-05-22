use std::rc::Rc;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes, CBORError};
use crate::tags_registry;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UUID(String);

impl UUID {
    pub fn from_str(uuid: &str) -> Self {
        Self(uuid.to_string())
    }

    pub fn from_string(uuid: String) -> Self {
        Self(uuid)
    }

    pub fn to_str(&self) -> &str {
        &self.0
    }

    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl CBORTagged for UUID {
    const CBOR_TAG: Tag = tags_registry::UUID;
}

impl CBOREncodable for UUID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for UUID {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.0.as_bytes()).cbor()
    }
}

impl CBORDecodable for UUID {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for UUID {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = Bytes::from_cbor(cbor)?;
        let uuid = String::from_utf8(bytes.data().to_vec()).map_err(|_| CBORError::InvalidFormat)?;
        Ok(Rc::new(Self::from_string(uuid)))
    }
}

impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UUID({})", self.0)
    }
}

// Convert from a string to a UUID.
impl From<&str> for UUID {
    fn from(uuid: &str) -> Self {
        Self::from_str(uuid)
    }
}

// Convert from a string to a UUID.
impl From<String> for UUID {
    fn from(uuid: String) -> Self {
        Self::from_string(uuid)
    }
}

// Convert from a UUID to a string.
impl From<UUID> for String {
    fn from(uuid: UUID) -> Self {
        uuid.0
    }
}

// Convert from a UUID to a string.
impl From<&UUID> for String {
    fn from(uuid: &UUID) -> Self {
        uuid.0.clone()
    }
}
