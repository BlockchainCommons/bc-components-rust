use std::ops::RangeInclusive;

use bc_rand::{
    RandomNumberGenerator, SecureRandomNumberGenerator,
    rng_next_in_closed_range, rng_random_data,
};
use bc_ur::prelude::*;

use crate::{Error, Result, tags};

/// Random salt used to decorrelate other information.
///
/// A `Salt` is a cryptographic primitive consisting of random data that is used
/// to modify the output of a cryptographic function. Salts are primarily used
/// in password hashing to defend against dictionary attacks, rainbow table
/// attacks, and pre-computation attacks. They are also used in other
/// cryptographic contexts to ensure uniqueness and prevent correlation between
/// different parts of a cryptosystem.
///
/// Unlike a [`Nonce`](crate::Nonce) which has a fixed size, a `Salt` in this
/// implementation can have a variable length (minimum 8 bytes). Different salt
/// creation methods are provided to generate salts of appropriate sizes for
/// different use cases.
///
/// # Minimum Size Requirement
///
/// For security reasons, salts must be at least 8 bytes long. Attempting to
/// create a salt with fewer than 8 bytes will result in an error.
///
/// # CBOR Serialization
///
/// `Salt` implements the `CBORTaggedCodable` trait, which means it can be
/// serialized to and deserialized from CBOR with a specific tag. The tag used
/// is `TAG_SALT` defined in the `tags` module.
///
/// # UR Serialization
///
/// When serialized as a Uniform Resource (UR), a `Salt` is represented as a
/// binary blob with the type "salt".
///
/// # Common Uses
///
/// - Password hashing and key derivation functions
/// - Preventing correlation in cryptographic protocols
/// - Randomizing data before encryption to prevent pattern recognition
/// - Adding entropy to improve security in various cryptographic functions
///
/// # Examples
///
/// Creating a salt with a specific length:
///
/// ```
/// use bc_components::Salt;
///
/// // Generate a salt with 16 bytes
/// let salt = Salt::new_with_len(16).unwrap();
/// assert_eq!(salt.len(), 16);
/// ```
///
/// Creating a salt with a length proportional to data size:
///
/// ```
/// use bc_components::Salt;
///
/// // Generate a salt proportional to 100 bytes of data
/// let salt = Salt::new_for_size(100);
///
/// // Salts for larger data will be larger (but still efficient)
/// let big_salt = Salt::new_for_size(1000);
/// assert!(big_salt.len() > salt.len());
/// ```
///
/// Creating a salt with a length in a specific range:
///
/// ```
/// use bc_components::Salt;
///
/// // Generate a salt with length between 16 and 32 bytes
/// let salt = Salt::new_in_range(16..=32).unwrap();
/// assert!(salt.len() >= 16 && salt.len() <= 32);
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Salt(Vec<u8>);

impl Salt {
    /// Return the length of the salt.
    pub fn len(&self) -> usize { self.0.len() }

    /// Return true if the salt is empty (this is not recommended).
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Create a new salt from data.
    pub fn from_data(data: impl AsRef<[u8]>) -> Self {
        Self(data.as_ref().to_vec())
    }

    /// Return the data of the salt.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

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
    pub fn new_with_len_using(
        count: usize,
        rng: &mut impl RandomNumberGenerator,
    ) -> Result<Self> {
        if count < 8 {
            return Err(Error::invalid_data(
                "salt",
                "length is too short (minimum 8 bytes)",
            ));
        }
        Ok(Self::from_data(rng_random_data(rng, count)))
    }

    /// Create a number of bytes of salt chosen randomly from the given range.
    ///
    /// If the minimum number of bytes is less than 8, this will return `None`.
    pub fn new_in_range(range: RangeInclusive<usize>) -> Result<Self> {
        if range.start() < &8 {
            return Err(Error::invalid_data(
                "salt",
                "minimum length is too short (minimum 8 bytes)",
            ));
        }
        let mut rng = SecureRandomNumberGenerator;
        Self::new_in_range_using(&range, &mut rng)
    }

    /// Create a number of bytes of salt chosen randomly from the given range.
    ///
    /// If the minimum number of bytes is less than 8, this will return `None`.
    pub fn new_in_range_using(
        range: &RangeInclusive<usize>,
        rng: &mut impl RandomNumberGenerator,
    ) -> Result<Self> {
        if range.start() < &8 {
            return Err(Error::invalid_data(
                "salt",
                "minimum length is too short (minimum 8 bytes)",
            ));
        }
        let count = rng_next_in_closed_range(rng, range);
        Self::new_with_len_using(count, rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of
    /// the object being salted.
    pub fn new_for_size(size: usize) -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_for_size_using(size, &mut rng)
    }

    /// Create a number of bytes of salt generally proportionate to the size of
    /// the object being salted.
    pub fn new_for_size_using(
        size: usize,
        rng: &mut impl RandomNumberGenerator,
    ) -> Self {
        let count = size as f64;
        let min_size = std::cmp::max(8, (count * 0.05).ceil() as usize);
        let max_size =
            std::cmp::max(min_size + 8, (count * 0.25).ceil() as usize);
        Self::new_in_range_using(&(min_size..=max_size), rng).unwrap()
    }

    /// Create a new salt from the given hexadecimal string.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data(hex::decode(hex.as_ref()).unwrap())
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String { hex::encode(self.as_bytes()) }
}

/// Allows accessing the underlying data as a byte slice reference.
impl<'a> From<&'a Salt> for &'a [u8] {
    fn from(value: &'a Salt) -> Self { value.as_bytes() }
}

/// Allows using a Salt as a reference to a byte slice.
impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Provides a self-reference, enabling API consistency with other types.
impl AsRef<Salt> for Salt {
    fn as_ref(&self) -> &Salt { self }
}

/// Identifies the CBOR tags used for Salt serialization.
impl CBORTagged for Salt {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_SALT]) }
}

/// Enables conversion of a Salt into a tagged CBOR value.
impl From<Salt> for CBOR {
    fn from(value: Salt) -> Self { value.tagged_cbor() }
}

/// Defines how a Salt is encoded as CBOR (as a byte string).
impl CBORTaggedEncodable for Salt {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.as_bytes()) }
}

/// Enables conversion from CBOR to Salt, with proper error handling.
impl TryFrom<CBOR> for Salt {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Defines how a Salt is decoded from CBOR.
impl CBORTaggedDecodable for Salt {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        let instance = Self::from_data(data);
        Ok(instance)
    }
}

/// Provides a debug representation showing the salt's length.
impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Salt({})", self.len())
    }
}

/// Enables cloning a Salt from a reference using From trait.
impl From<&Salt> for Salt {
    fn from(salt: &Salt) -> Self { salt.clone() }
}

/// Converts a Salt into a `Vec<u8>` containing the salt bytes.
impl From<Salt> for Vec<u8> {
    fn from(salt: Salt) -> Self { salt.0.to_vec() }
}

/// Converts a Salt reference into a `Vec<u8>` containing the salt bytes.
impl From<&Salt> for Vec<u8> {
    fn from(salt: &Salt) -> Self { salt.0.to_vec() }
}
