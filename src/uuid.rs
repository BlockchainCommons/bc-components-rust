use std::str::FromStr;

use anyhow::bail;
use dcbor::prelude::*;
use crate::tags;

/// A UUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UUID([u8; Self::UUID_SIZE]);

impl UUID {
    pub const UUID_SIZE: usize = 16;

    /// Creates a new type 4 (random) UUID.
    pub fn new() -> Self {
        let mut uuid = [0u8; Self::UUID_SIZE];
        bc_rand::fill_random_data(&mut uuid);
        uuid[6] = (uuid[6] & 0x0F) | 0x40; // set version to 4
        uuid[8] = (uuid[8] & 0x3F) | 0x80; // set variant to 2
        Self(uuid)
    }

    /// Restores a UUID from data.
    pub fn from_data(data: [u8; Self::UUID_SIZE]) -> Self {
        Self(data)
    }

    /// Restores a UUID from data.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() != Self::UUID_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::UUID_SIZE];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Returns the data of the UUID.
    pub fn data(&self) -> &[u8; Self::UUID_SIZE] {
        self.into()
    }
}

impl Default for UUID {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a UUID> for &'a [u8; UUID::UUID_SIZE] {
    fn from(value: &'a UUID) -> Self {
        &value.0
    }
}

impl AsRef<[u8]> for UUID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<UUID> for UUID {
    fn as_ref(&self) -> &UUID {
        self
    }
}

impl CBORTagged for UUID {
    const CBOR_TAG: Tag = tags::UUID;
}

impl CBOREncodable for UUID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl From<UUID> for CBOR {
    fn from(value: UUID) -> Self {
        value.cbor()
    }
}

impl CBORTaggedEncodable for UUID {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.0)
    }
}

impl CBORDecodable for UUID {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl TryFrom<CBOR> for UUID {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(&cbor)
    }
}

impl TryFrom<&CBOR> for UUID {
    type Error = anyhow::Error;

    fn try_from(cbor: &CBOR) -> Result<Self, Self::Error> {
        UUID::from_cbor(cbor)
    }
}

impl CBORTaggedDecodable for UUID {
    fn from_untagged_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        let bytes = CBOR::expect_byte_string(cbor)?;
        if bytes.len() != Self::UUID_SIZE {
            bail!("invalid UUID size");
        }
        let mut uuid = [0u8; Self::UUID_SIZE];
        uuid.copy_from_slice(&bytes);
        Ok(Self::from_data(uuid))
    }
}

impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

// Convert from a UUID to a string.
impl From<UUID> for String {
    fn from(uuid: UUID) -> Self {
        String::from(&uuid)
    }
}

// Convert from a UUID to a string.
impl From<&UUID> for String {
    fn from(uuid: &UUID) -> Self {
        let hex = hex::encode(uuid.0);
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    }
}

impl FromStr for UUID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s.replace('-', "");
        let bytes = hex::decode(s).unwrap();
        let mut uuid = [0u8; Self::UUID_SIZE];
        uuid.copy_from_slice(&bytes);
        Ok(Self::from_data(uuid))
    }
}
