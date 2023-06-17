use std::ops::RangeInclusive;
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable};
use bc_crypto::{RandomNumberGenerator, SecureRandomNumberGenerator};
use crate::tags;

#[derive(Clone, Eq, PartialEq)]
pub struct Salt(Vec<u8>);

impl Salt {
    /// Create a new salt from data.
    pub fn from_data(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    /// Create a new salt from data.
    pub fn from_data_ref<T>(data: &T) -> Self where T: AsRef<[u8]> {
        Self::from_data(data.as_ref())
    }

    /// Return the data of the salt.
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    /// Create a specific number of bytes of salt.
    ///
    /// If the number of bytes is less than 8, this will return `None`.
    pub fn new_with_len(count: usize) -> Option<Self> {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_with_len_using(count, &mut rng)
    }

    /// Create a specific number of bytes of salt.
    ///
    /// If the number of bytes is less than 8, this will return `None`.
    pub fn new_with_len_using<R>(count: usize, rng: &mut R) -> Option<Self>
    where R: RandomNumberGenerator
    {
        if count < 8 {
            return None;
        }
        Some(Self(rng.random_data(count)))
    }

    /// Create a number of bytes of salt chosen randomly from the given range.
    ///
    /// If the minimum number of bytes is less than 8, this will return `None`.
    pub fn new_in_range(range: RangeInclusive<usize>) -> Option<Self> {
        if range.start() < &8 {
            return None;
        }
        let mut rng = SecureRandomNumberGenerator;
        Self::new_in_range_using(&range, &mut rng)
    }

    /// Create a number of bytes of salt chosen randomly from the given range.
    ///
    /// If the minimum number of bytes is less than 8, this will return `None`.
    pub fn new_in_range_using<R>(range: &RangeInclusive<usize>, rng: &mut R) -> Option<Self>
    where R: RandomNumberGenerator
    {
        if range.start() < &8 {
            return None;
        }
        let count = rng.next_in_closed_range(range);
        Self::new_with_len_using(count, rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    pub fn new_for_size(size: usize) -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_for_size_using(size, &mut rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of the object being salted.
    pub fn new_for_size_using<R>(size: usize, rng: &mut R) -> Self
    where R: RandomNumberGenerator
    {
        let count = size as f64;
        let min_size = std::cmp::max(8, (count * 0.05).ceil() as usize);
        let max_size = std::cmp::max(min_size + 8, (count * 0.25).ceil() as usize);
        Self::new_in_range_using(&(min_size..=max_size), rng).unwrap()
    }

    /// Create a new salt from the given hexadecimal string.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap())
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

impl CBORTagged for Salt {
    const CBOR_TAG: Tag = tags::SALT;
}

impl CBOREncodable for Salt {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Salt {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.data())
    }
}

impl CBORDecodable for Salt {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Salt {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data_ref(&data);
        Ok(instance)
    }
}

impl UREncodable for Salt { }

impl URDecodable for Salt { }

impl URCodable for Salt { }

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Salt({})", self.hex())
    }
}

// Convert from a thing that can be referenced as an array of bytes to a Salt.
impl<T: AsRef<[u8]>> From<T> for Salt {
    fn from(data: T) -> Self {
        Self::from_data_ref(&data)
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
