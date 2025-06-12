use anyhow::{Result, bail};
use bc_rand::random_data;
use bc_ur::prelude::*;

use crate::tags;

/// An "Apparently Random Identifier" (ARID)
///
/// An ARID is a cryptographically strong, universally unique identifier with
/// the following properties:
/// - Non-correlatability: The sequence of bits cannot be correlated with its
///   referent or any other ARID
/// - Neutral semantics: Contains no inherent type information
/// - Open generation: Any method of generation is allowed as long as it
///   produces statistically random bits
/// - Minimum strength: Must be 256 bits (32 bytes) in length
/// - Cryptographic suitability: Can be used as inputs to cryptographic
///   constructs
///
/// Unlike digests/hashes which identify a fixed, immutable state of data, ARIDs
/// can serve as stable identifiers for mutable data structures.
///
/// ARIDs should not be confused with or cast to/from other identifier types
/// (like UUIDs), used as nonces, keys, or cryptographic seeds.
///
/// As defined in [BCR-2022-002](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-arid.md).
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ARID([u8; Self::ARID_SIZE]);

impl ARID {
    pub const ARID_SIZE: usize = 32;

    /// Create a new random ARID.
    pub fn new() -> Self {
        let data = random_data(Self::ARID_SIZE);
        Self::from_data_ref(data).unwrap()
    }

    /// Restore a ARID from a fixed-size array of bytes.
    pub fn from_data(data: [u8; Self::ARID_SIZE]) -> Self { Self(data) }

    /// Create a new ARID from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::ARID_SIZE {
            bail!("Invalid ARID size");
        }
        let mut arr = [0u8; Self::ARID_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get the data of the ARID as an array of bytes.
    pub fn data(&self) -> &[u8; Self::ARID_SIZE] { &self.0 }

    /// Get the data of the ARID as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Create a new ARID from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String { hex::encode(self.as_bytes()) }

    /// The first four bytes of the ARID as a hexadecimal string.
    pub fn short_description(&self) -> String { hex::encode(&self.0[0..4]) }
}

impl AsRef<[u8]> for ARID {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements the Default trait to create a new random ARID.
impl Default for ARID {
    fn default() -> Self { Self::new() }
}

/// Implements conversion from an ARID reference to a byte slice reference.
impl<'a> From<&'a ARID> for &'a [u8] {
    fn from(value: &'a ARID) -> Self { &value.0 }
}

/// Implements the CBORTagged trait to provide CBOR tag information.
impl CBORTagged for ARID {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_ARID]) }
}

/// Implements conversion from ARID to CBOR for serialization.
impl From<ARID> for CBOR {
    fn from(value: ARID) -> Self { value.tagged_cbor() }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
impl CBORTaggedEncodable for ARID {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.as_bytes()) }
}

/// Implements `TryFrom<CBOR>` for ARID to support conversion from CBOR data.
impl TryFrom<CBOR> for ARID {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for ARID {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        Ok(Self::from_data_ref(data)?)
    }
}

/// Implements Debug formatting for ARID showing the full hex representation.
impl std::fmt::Debug for ARID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ARID({})", self.hex())
    }
}

/// Implements Display formatting for ARID showing the hex representation.
impl std::fmt::Display for ARID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ARID({})", self.hex())
    }
}

/// Implements PartialOrd to allow ARIDs to be compared and ordered.
impl PartialOrd for ARID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}
