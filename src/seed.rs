use bc_rand::{RandomNumberGenerator, rng_random_data};
use bc_ur::prelude::*;

use crate::{Error, PrivateKeyDataProvider, Result, tags};

/// A cryptographic seed for deterministic key generation.
///
/// A `Seed` is a source of entropy used to generate cryptographic keys in a
/// deterministic manner. Unlike randomly generated keys, seed-derived keys can
/// be recreated if you have the original seed, making them useful for backup
/// and recovery scenarios.
///
/// This implementation of `Seed` includes the random seed data as well as
/// optional metadata:
/// - A name (for identifying the seed)
/// - A note (for storing additional information)
/// - A creation date
///
/// The minimum seed length is 16 bytes to ensure sufficient security and
/// entropy.
///
/// # CBOR Serialization
///
/// `Seed` implements the `CBORTaggedCodable` trait, which means it can be
/// serialized to and deserialized from CBOR with specific tags. The tags used
/// are `TAG_SEED` and the older `TAG_SEED_V1` for backward compatibility.
///
/// When serialized to CBOR, a `Seed` is represented as a map with the following
/// keys:
/// - 1: The seed data (required)
/// - 2: The creation date (optional)
/// - 3: The name (optional, omitted if empty)
/// - 4: The note (optional, omitted if empty)
///
/// # UR Serialization
///
/// When serialized as a Uniform Resource (UR), a `Seed` is represented with the
/// type "seed".
///
/// # Key Derivation
///
/// A `Seed` implements the `PrivateKeyDataProvider` trait, which means it can
/// be used as a source of entropy for deriving private keys in various
/// cryptographic schemes.
///
/// # Examples
///
/// Creating a new random seed:
///
/// ```
/// use bc_components::Seed;
///
/// // Create a new random seed with default length (16 bytes)
/// let seed = Seed::new();
/// ```
///
/// Creating a seed with a specific length:
///
/// ```
/// use bc_components::Seed;
///
/// // Create a seed with 32 bytes of entropy
/// let seed = Seed::new_with_len(32).unwrap();
/// ```
///
/// Creating a seed with metadata:
///
/// ```
/// use bc_components::Seed;
/// use dcbor::prelude::*;
///
/// // Create seed data
/// let data = vec![0u8; 16];
///
/// // Create a seed with name, note, and creation date
/// let mut seed = Seed::new_opt(
///     data,
///     Some("Wallet Backup".to_string()),
///     Some("Cold storage backup for main wallet".to_string()),
///     Some(Date::now()),
/// )
/// .unwrap();
///
/// // Modify metadata
/// seed.set_name("Updated Wallet Backup");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Seed {
    data: Vec<u8>,
    name: String,
    note: String,
    creation_date: Option<Date>,
}

impl Seed {
    pub const MIN_SEED_LENGTH: usize = 16;

    /// Create a new random seed.
    ///
    /// The length of the seed will be 16 bytes.
    pub fn new() -> Self { Self::new_with_len(Self::MIN_SEED_LENGTH).unwrap() }

    /// Create a new random seed with a specified length.
    ///
    /// If the number of bytes is less than 16, this will return `None`.
    pub fn new_with_len(count: usize) -> Result<Self> {
        let mut rng = bc_rand::SecureRandomNumberGenerator;
        Self::new_with_len_using(count, &mut rng)
    }

    /// Create a new random seed with a specified length.
    ///
    /// If the number of bytes is less than 16, this will return `None`.
    pub fn new_with_len_using(
        count: usize,
        rng: &mut impl RandomNumberGenerator,
    ) -> Result<Self> {
        let data = rng_random_data(rng, count);
        Self::new_opt(data, None, None, None)
    }

    /// Create a new seed from the data and options.
    ///
    /// If the data is less than 16 bytes, this will return `None`.
    pub fn new_opt(
        data: impl AsRef<[u8]>,
        name: Option<String>,
        note: Option<String>,
        creation_date: Option<Date>,
    ) -> Result<Self> {
        let data = data.as_ref().to_vec();
        if data.len() < Self::MIN_SEED_LENGTH {
            return Err(Error::invalid_data(
                "seed",
                format!(
                    "data is too short (minimum {} bytes)",
                    Self::MIN_SEED_LENGTH
                ),
            ));
        }
        Ok(Self {
            data,
            name: name.unwrap_or_default(),
            note: note.unwrap_or_default(),
            creation_date,
        })
    }

    /// Return the data of the seed.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Return the name of the seed.
    pub fn name(&self) -> &str { &self.name }

    /// Set the name of the seed.
    pub fn set_name(&mut self, name: &str) { self.name = name.to_string(); }

    /// Return the note of the seed.
    pub fn note(&self) -> &str { &self.note }

    /// Set the note of the seed.
    pub fn set_note(&mut self, note: &str) { self.note = note.to_string(); }

    /// Return the creation date of the seed.
    pub fn creation_date(&self) -> &Option<Date> { &self.creation_date }

    /// Set the creation date of the seed.
    pub fn set_creation_date(&mut self, creation_date: Option<Date>) {
        self.creation_date = creation_date;
    }
}

/// Provides a default implementation that creates a new random seed with the
/// minimum length.
impl Default for Seed {
    fn default() -> Self { Self::new() }
}

/// Allows using a Seed as a reference to a byte slice.
impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] { self.data.as_ref() }
}

/// Provides a self-reference, enabling API consistency with other types.
impl AsRef<Seed> for Seed {
    fn as_ref(&self) -> &Seed { self }
}

/// Implements PrivateKeyDataProvider to use seed data for key derivation.
impl PrivateKeyDataProvider for Seed {
    fn private_key_data(&self) -> Vec<u8> { self.as_bytes().to_vec() }
}

/// Identifies the CBOR tags used for Seed serialization, including the legacy
/// tag.
impl CBORTagged for Seed {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SEED, tags::TAG_SEED_V1])
    }
}

/// Enables conversion of a Seed into a tagged CBOR value.
impl From<Seed> for CBOR {
    fn from(value: Seed) -> Self { value.tagged_cbor() }
}

/// Defines how a Seed is encoded as CBOR (as a map with data and metadata).
impl CBORTaggedEncodable for Seed {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = dcbor::Map::new();
        map.insert(1, CBOR::to_byte_string(self.as_bytes()));
        if let Some(creation_date) = self.creation_date().clone() {
            map.insert(2, creation_date);
        }
        if !self.name().is_empty() {
            map.insert(3, self.name());
        }
        if !self.note().is_empty() {
            map.insert(4, self.note());
        }
        map.into()
    }
}

/// Enables conversion from CBOR to Seed, with proper error handling.
impl TryFrom<CBOR> for Seed {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Defines how a Seed is decoded from CBOR.
impl CBORTaggedDecodable for Seed {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let map = cbor.try_into_map()?;
        let data = map
            .extract::<i32, CBOR>(1)?
            .try_into_byte_string()?
            .to_vec();
        if data.is_empty() {
            return Err("Seed data is empty".into());
        }
        let creation_date = map.get::<i32, Date>(2);
        let name = map.get::<i32, String>(3);
        let note = map.get::<i32, String>(4);
        Ok(Self::new_opt(data, name, note, creation_date)?)
    }
}
