use bc_rand::{rng_random_data, RandomNumberGenerator};
use bc_ur::prelude::*;
use crate::{ tags, PrivateKeyDataProvider };
use anyhow::{ bail, Result, Error };

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Seed {
    data: Vec<u8>,
    name: String,
    note: String,
    creation_date: Option<dcbor::Date>,
}

impl Seed {
    pub const MIN_SEED_LENGTH: usize = 16;

    /// Create a new random seed.
    ///
    /// The length of the seed will be 16 bytes.
    pub fn new() -> Self {
        Self::new_with_len(Self::MIN_SEED_LENGTH).unwrap()
    }

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
        rng: &mut impl RandomNumberGenerator
    ) -> Result<Self> {
        let data = rng_random_data(rng, count);
        Self::new_opt(data, None, None, None)
    }

    /// Create a new seed from the data and options.
    ///
    /// If the data is less than 16 bytes, this will return `None`.
    pub fn new_opt(
        data: impl Into<Vec<u8>>,
        name: Option<String>,
        note: Option<String>,
        creation_date: Option<dcbor::Date>
    ) -> Result<Self> {
        let data = data.into();
        if data.len() < Self::MIN_SEED_LENGTH {
            bail!("Seed data is too short");
        }
        Ok(Self {
            data,
            name: name.unwrap_or_default(),
            note: note.unwrap_or_default(),
            creation_date,
        })
    }

    /// Return the data of the seed.
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Return the name of the seed.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the name of the seed.
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    /// Return the note of the seed.
    pub fn note(&self) -> &str {
        &self.note
    }

    /// Set the note of the seed.
    pub fn set_note(&mut self, note: &str) {
        self.note = note.to_string();
    }

    /// Return the creation date of the seed.
    pub fn creation_date(&self) -> &Option<dcbor::Date> {
        &self.creation_date
    }

    /// Set the creation date of the seed.
    pub fn set_creation_date(&mut self, creation_date: Option<dcbor::Date>) {
        self.creation_date = creation_date;
    }
}

impl Default for Seed {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsRef<Seed> for Seed {
    fn as_ref(&self) -> &Seed {
        self
    }
}

impl PrivateKeyDataProvider for Seed {
    fn private_key_data(&self) -> Vec<u8> {
        self.data().clone()
    }
}

impl CBORTagged for Seed {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SEED, tags::TAG_SEED_V1])
    }
}

impl From<Seed> for CBOR {
    fn from(value: Seed) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Seed {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = dcbor::Map::new();
        map.insert(1, CBOR::to_byte_string(self.data()));
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

impl TryFrom<CBOR> for Seed {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Seed {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        let map = cbor.try_into_map()?;
        let data = map.extract::<i32, CBOR>(1)?.try_into_byte_string()?.to_vec();
        if data.is_empty() {
            bail!("Seed data is empty");
        }
        let creation_date = map.get::<i32, dcbor::Date>(2);
        let name = map.get::<i32, String>(3);
        let note = map.get::<i32, String>(4);
        Self::new_opt(data, name, note, creation_date)
    }
}
