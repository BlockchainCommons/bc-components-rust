use std::rc::Rc;
use bc_crypto::random_data;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes, CBORError};

use crate::tags_registry;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CID ([u8; Self::CID_LENGTH]);

impl CID {
    pub const CID_LENGTH: usize = 32;

    /// Create a new CID from raw bytes.
    pub fn from_raw(raw: [u8; Self::CID_LENGTH]) -> Self {
        Self(raw)
    }

    /// Create a new CID from raw bytes.
    pub fn from_raw_data<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let raw = data.as_ref();
        if raw.len() != Self::CID_LENGTH {
            return None;
        }
        let mut arr = [0u8; Self::CID_LENGTH];
        arr.copy_from_slice(&raw);
        Some(Self::from_raw(arr))
    }

    /// Create a new random CID.
    pub fn new() -> Self {
        let data = random_data(Self::CID_LENGTH);
        Self::from_raw_data(&data).unwrap()
    }

    /// Get the raw value of the CID.
    pub fn raw(&self) -> &[u8] {
        &self.0
    }

    /// Create a new CID from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_raw_data(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The raw value as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.raw())
    }
}

impl CBORTagged for CID {
    const CBOR_TAG: Tag = tags_registry::COMMON_IDENTIFIER;
}

impl CBOREncodable for CID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for CID {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::Bytes(Bytes::from(self.raw()))
    }
}

impl CBORDecodable for CID {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for CID {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = Bytes::from_cbor(untagged_cbor)?;
        let data = bytes.data();
        let instance = Self::from_raw_data(&data).ok_or(CBORError::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl std::fmt::Display for CID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "CID({})", self.hex())
    }
}

impl PartialOrd for CID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}
