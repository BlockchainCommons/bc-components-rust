use bc_rand::random_data;
use bc_ur::prelude::*;

use crate::tags;
use anyhow::bail;

/// An "Apparently Random Identifier" (ARID)
///
/// As defined in [BCR-2022-002](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-arid.md).
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ARID ([u8; Self::ARID_SIZE]);

impl ARID {
    pub const ARID_SIZE: usize = 32;

    /// Create a new random ARID.
    pub fn new() -> Self {
        let data = random_data(Self::ARID_SIZE);
        Self::from_data_ref(data).unwrap()
    }

    /// Restore a ARID from a fixed-size array of bytes.
    pub fn from_data(data: [u8; Self::ARID_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new ARID from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::ARID_SIZE {
            bail!("Invalid ARID size");
        }
        let mut arr = [0u8; Self::ARID_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get the data of the ARID.
    pub fn data(&self) -> &[u8] {
        self.into()
    }

    /// Create a new ARID from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
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
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ARID]
    }
}

impl CBOREncodable for ARID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl From<ARID> for CBOR {
    fn from(value: ARID) -> Self {
        value.cbor()
    }
}

impl CBORTaggedEncodable for ARID {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.data())
    }
}

impl CBORDecodable for ARID {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl TryFrom<CBOR> for ARID {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(&cbor)
    }
}

impl TryFrom<&CBOR> for ARID {
    type Error = anyhow::Error;

    fn try_from(cbor: &CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(cbor)
    }
}

impl CBORTaggedDecodable for ARID {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> anyhow::Result<Self> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        Self::from_data_ref(&data)
    }
}

impl std::fmt::Debug for ARID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ARID({})", self.hex())
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

impl UREncodable for ARID { }

impl URDecodable for ARID { }

impl URCodable for ARID { }
