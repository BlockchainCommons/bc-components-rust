use bc_crypto::random_data;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, expect_byte_string, byte_string};

use crate::tags_registry;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CID ([u8; Self::CID_SIZE]);

impl CID {
    pub const CID_SIZE: usize = 32;

    /// Create a new CID from bytes.
    pub fn from_data(data: [u8; Self::CID_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new CID from bytes.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::CID_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::CID_SIZE];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Create a new random CID.
    pub fn new() -> Self {
        let data = random_data(Self::CID_SIZE);
        Self::from_data_ref(&data).unwrap()
    }

    /// Get the data of the CID.
    pub fn data(&self) -> &[u8] {
        self.into()
    }

    /// Create a new CID from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }

    /// The first four bytes of the CID as a hexadecimal string.
    pub fn short_description(&self) -> String {
        hex::encode(&self.0[0..4])
    }
}

impl<'a> From<&'a CID> for &'a [u8] {
    fn from(value: &'a CID) -> Self {
        &value.0
    }
}

impl CBORTagged for CID {
    const CBOR_TAG: Tag = tags_registry::CID;
}

impl CBOREncodable for CID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for CID {
    fn untagged_cbor(&self) -> CBOR {
        byte_string(self.data())
    }
}

impl CBORDecodable for CID {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for CID {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(instance)
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
