use bc_crypto::random_data;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable};

use crate::tags;

/// An "Apparently Random Identifier" (ARID)
///
/// As defined in [BCR-2022-002](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-arid.md).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ARID ([u8; Self::ARID_SIZE]);

impl ARID {
    pub const ARID_SIZE: usize = 32;

    /// Create a new random ARID.
    pub fn new() -> Self {
        let data = random_data(Self::ARID_SIZE);
        Self::from_data_ref(&data).unwrap()
    }

    /// Restore a ARID from a fixed-size array of bytes.
    pub fn from_data(data: [u8; Self::ARID_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new ARID from a reference to an array of bytes.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::ARID_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::ARID_SIZE];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Get the data of the ARID.
    pub fn data(&self) -> &[u8] {
        self.into()
    }

    /// Create a new ARID from the given hexadecimal string.
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

    /// The first four bytes of the ARID as a hexadecimal string.
    pub fn short_description(&self) -> String {
        hex::encode(&self.0[0..4])
    }
}

impl Default for ARID {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a ARID> for &'a [u8] {
    fn from(value: &'a ARID) -> Self {
        &value.0
    }
}

impl AsRef<ARID> for ARID {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl CBORTagged for ARID {
    const CBOR_TAG: Tag = tags::ARID;
}

impl CBOREncodable for ARID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ARID {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.data())
    }
}

impl CBORDecodable for ARID {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for ARID {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(instance)
    }
}

impl std::fmt::Display for ARID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ARID({})", self.hex())
    }
}

impl PartialOrd for ARID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}
