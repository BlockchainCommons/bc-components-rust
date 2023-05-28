use std::{rc::Rc, str::FromStr};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes, Error};
use crate::tags_registry;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UUID(String);

impl UUID {
    pub fn new<T>(uuid: T) -> Self where T: Into<String> {
        Self(uuid.into())
    }
}

impl FromStr for UUID {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
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
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for UUID {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, Error> {
        let bytes = Bytes::from_cbor(cbor)?;
        let uuid = String::from_utf8(bytes.data().to_vec()).map_err(|_| Error::InvalidFormat)?;
        Ok(Rc::new(Self::new(uuid)))
    }
}

impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Convert from a string to a UUID.
impl From<&str> for UUID {
    fn from(uuid: &str) -> Self {
        Self::new(uuid)
    }
}

// Convert from a string to a UUID.
impl From<String> for UUID {
    fn from(uuid: String) -> Self {
        Self::new(uuid)
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
