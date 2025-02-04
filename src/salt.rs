use std::ops::RangeInclusive;
use bc_ur::prelude::*;
use bc_rand::{ rng_next_in_closed_range, rng_random_data, RandomNumberGenerator, SecureRandomNumberGenerator };
use crate::tags;
use anyhow::{ bail, Result, Error };

/// Random salt used to decorrelate other information.
#[derive(Clone, Eq, PartialEq)]
pub struct Salt(Vec<u8>);

impl Salt {
    /// Return the length of the salt.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return true if the salt is empty (this is not recommended).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Create a new salt from data.
    pub fn from_data(data: impl Into<Vec<u8>>) -> Self {
        Self(data.into())
    }

    /// Return the data of the salt.
    pub fn data(&self) -> &Vec<u8> {
        &self.0
    }

    /// Create a specific number of bytes of salt.
    ///
    /// If the number of bytes is less than 8, this will return `None`.
    pub fn new_with_len(count: usize) -> Result<Self> {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_with_len_using(count, &mut rng)
    }

    /// Create a specific number of bytes of salt.
    ///
    /// If the number of bytes is less than 8, this will return `None`.
    pub fn new_with_len_using(count: usize, rng: &mut impl RandomNumberGenerator) -> Result<Self> {
        if count < 8 {
            bail!("Salt length is too short");
        }
        Ok(Self::from_data(rng_random_data(rng, count)))
    }

    /// Create a number of bytes of salt chosen randomly from the given range.
    ///
    /// If the minimum number of bytes is less than 8, this will return `None`.
    pub fn new_in_range(range: RangeInclusive<usize>) -> Result<Self> {
        if range.start() < &8 {
            bail!("Salt length is too short");
        }
        let mut rng = SecureRandomNumberGenerator;
        Self::new_in_range_using(&range, &mut rng)
    }

    /// Create a number of bytes of salt chosen randomly from the given range.
    ///
    /// If the minimum number of bytes is less than 8, this will return `None`.
    pub fn new_in_range_using(
        range: &RangeInclusive<usize>,
        rng: &mut impl RandomNumberGenerator
    ) -> Result<Self> {
        if range.start() < &8 {
            bail!("Salt length is too short");
        }
        let count = rng_next_in_closed_range(rng, range);
        Self::new_with_len_using(count, rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    pub fn new_for_size(size: usize) -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_for_size_using(size, &mut rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    pub fn new_for_size_using(size: usize, rng: &mut impl RandomNumberGenerator) -> Self {
        let count = size as f64;
        let min_size = std::cmp::max(8, (count * 0.05).ceil() as usize);
        let max_size = std::cmp::max(min_size + 8, (count * 0.25).ceil() as usize);
        Self::new_in_range_using(&(min_size..=max_size), rng).unwrap()
    }

    /// Create a new salt from the given hexadecimal string.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data(hex::decode(hex.as_ref()).unwrap())
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl<'a> From<&'a Salt> for &'a [u8] {
    fn from(value: &'a Salt) -> Self {
        value.data()
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsRef<Salt> for Salt {
    fn as_ref(&self) -> &Salt {
        self
    }
}

impl CBORTagged for Salt {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SALT])
    }
}

impl From<Salt> for CBOR {
    fn from(value: Salt) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Salt {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.data())
    }
}

impl TryFrom<CBOR> for Salt {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Salt {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        let instance = Self::from_data(data);
        Ok(instance)
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Salt({})", self.len())
    }
}

// Convert from a reference to a byte vector to a Salt.
impl From<&Salt> for Salt {
    fn from(salt: &Salt) -> Self {
        salt.clone()
    }
}

// Convert from a byte vector to a Salt.
impl From<Salt> for Vec<u8> {
    fn from(salt: Salt) -> Self {
        salt.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a Salt.
impl From<&Salt> for Vec<u8> {
    fn from(salt: &Salt) -> Self {
        salt.0.to_vec()
    }
}
