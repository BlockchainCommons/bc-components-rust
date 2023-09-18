use anyhow::bail;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable};
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
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
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

impl CBORTagged for UUID {
    const CBOR_TAG: Tag = tags::UUID;
}

impl CBOREncodable for UUID {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for UUID {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.0)
    }
}

impl CBORDecodable for UUID {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for UUID {
    fn from_untagged_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        let bytes = CBOR::expect_byte_string(cbor)?;
        if bytes.len() != Self::UUID_SIZE {
            bail!("invalid UUID size");
        }
        let mut uuid = [0u8; Self::UUID_SIZE];
        uuid.copy_from_slice(bytes);
        Ok(Self::from_data(uuid))
    }
}

impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// Convert from a UUID to a string.
impl From<UUID> for String {
    fn from(uuid: UUID) -> Self {
        hex::encode(uuid.0)
    }
}

// Convert from a UUID to a string.
impl From<&UUID> for String {
    fn from(uuid: &UUID) -> Self {
        hex::encode(uuid.0)
    }
}
