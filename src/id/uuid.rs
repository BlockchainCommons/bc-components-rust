use std::str::FromStr;

use anyhow::{Error, Result};
use dcbor::prelude::*;

use crate::tags;

/// A Universally Unique Identifier (UUID).
///
/// UUIDs are 128-bit (16-byte) identifiers that are designed to be unique
/// across space and time. This implementation creates type 4 (random) UUIDs,
/// following the UUID specification:
///
/// - Version field (bits 48-51) is set to 4, indicating a random UUID
/// - Variant field (bits 64-65) is set to 2, indicating RFC 4122/DCE 1.1 UUID
///   variant
///
/// Unlike ARIDs, UUIDs:
/// - Are shorter (128 bits vs 256 bits)
/// - Contain version and variant metadata within the identifier
/// - Have a canonical string representation with 5 groups separated by hyphens
///
/// The canonical textual representation of a UUID takes the form:
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` where each `x` is a hexadecimal
/// digit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UUID([u8; Self::UUID_SIZE]);

impl UUID {
    pub const UUID_SIZE: usize = 16;

    /// Creates a new type 4 (random) UUID.
    pub fn new() -> Self {
        let mut uuid = [0u8; Self::UUID_SIZE];
        bc_rand::fill_random_data(&mut uuid);
        uuid[6] = (uuid[6] & 0x0f) | 0x40; // set version to 4
        uuid[8] = (uuid[8] & 0x3f) | 0x80; // set variant to 2
        Self(uuid)
    }

    /// Restores a UUID from data.
    pub fn from_data(data: [u8; Self::UUID_SIZE]) -> Self { Self(data) }

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
    pub fn data(&self) -> &[u8; Self::UUID_SIZE] { self.into() }

    /// Get the data of the UUID as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }
}

/// Implements Default for UUID to create a new random UUID.
impl Default for UUID {
    fn default() -> Self { Self::new() }
}

/// Implements conversion from a UUID reference to a byte array reference.
impl<'a> From<&'a UUID> for &'a [u8; UUID::UUID_SIZE] {
    fn from(value: &'a UUID) -> Self { &value.0 }
}

/// Implements AsRef<[u8]> to allow UUID to be treated as a byte slice.
impl AsRef<[u8]> for UUID {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements CBORTagged trait to provide CBOR tag information.
impl CBORTagged for UUID {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_UUID]) }
}

/// Implements conversion from UUID to CBOR for serialization.
impl From<UUID> for CBOR {
    fn from(value: UUID) -> Self { value.tagged_cbor() }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
impl CBORTaggedEncodable for UUID {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.0) }
}

/// Implements `TryFrom<CBOR>` for UUID to support conversion from CBOR data.
impl TryFrom<CBOR> for UUID {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for UUID {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let bytes = CBOR::try_into_byte_string(cbor)?;
        if bytes.len() != Self::UUID_SIZE {
            return Err("invalid UUID size".into());
        }
        let mut uuid = [0u8; Self::UUID_SIZE];
        uuid.copy_from_slice(&bytes);
        Ok(Self::from_data(uuid))
    }
}

/// Implements Display for UUID to format it in the standard UUID string format.
impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

/// Implements conversion from UUID to String in the standard format with
/// dashes.
impl From<UUID> for String {
    fn from(uuid: UUID) -> Self {
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

/// Implements conversion from UUID reference to String.
impl From<&UUID> for String {
    fn from(uuid: &UUID) -> Self { String::from(*uuid) }
}

/// Implements string parsing to create a UUID.
impl FromStr for UUID {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s.replace('-', "");
        let bytes = hex::decode(s).unwrap();
        let mut uuid = [0u8; Self::UUID_SIZE];
        uuid.copy_from_slice(&bytes);
        Ok(Self::from_data(uuid))
    }
}
