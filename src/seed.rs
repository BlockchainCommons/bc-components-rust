use bc_ur::prelude::*;
use crate::{tags, PrivateKeysDataProvider};
use anyhow::bail;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Seed {
    data: Vec<u8>,
    name: String,
    note: String,
    creation_date: Option<dcbor::Date>,
}

impl Seed {
    pub const MIN_SEED_LENGTH : usize = 16;

    /// Create a new random seed.
    ///
    /// The length of the seed will be 16 bytes.
    pub fn new() -> Self {
        Self::new_with_len(Self::MIN_SEED_LENGTH).unwrap()
    }

    /// Create a new random seed with a specified length.
    ///
    /// If the number of bytes is less than 16, this will return `None`.
    pub fn new_with_len(count: usize) -> anyhow::Result<Self> {
        let mut rng = bc_rand::SecureRandomNumberGenerator;
        Self::new_with_len_using(count, &mut rng)
    }

    /// Create a new random seed with a specified length.
    ///
    /// If the number of bytes is less than 16, this will return `None`.
    pub fn new_with_len_using<R>(count: usize, rng: &mut R) -> anyhow::Result<Self>
    where
        R: bc_rand::RandomNumberGenerator,
    {
        let data = rng.random_data(count);
        Self::new_opt(data, None, None, None)
    }

    /// Create a new seed from the data and options.
    ///
    /// If the data is less than 16 bytes, this will return `None`.
    pub fn new_opt<T>(data: T, name: Option<String>, note: Option<String>, creation_date: Option<dcbor::Date>) -> anyhow::Result<Self>
    where
        T: Into<Vec<u8>>,
    {
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

impl PrivateKeysDataProvider for Seed {
    fn private_keys_data(&self) -> Vec<u8> {
        self.data().to_vec()
    }
}

impl CBORTagged for Seed {
    const CBOR_TAG: Tag = tags::SEED;
}

impl CBOREncodable for Seed {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Seed {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = dcbor::Map::new();
        map.insert_into(1, CBOR::byte_string(self.data()));
        if let Some(creation_date) = self.creation_date() {
            map.insert_into(2, creation_date);
        }
        if !self.name().is_empty() {
            map.insert_into(3, self.name());
        }
        if !self.note().is_empty() {
            map.insert_into(4, self.note());
        }
        map.cbor()
    }
}

impl CBORDecodable for Seed {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Seed {
    fn from_untagged_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        let map = cbor.expect_map()?;
        let data = map.extract::<i32, CBOR>(1)?.expect_byte_string()?.to_vec();
        if data.is_empty() {
            bail!("Seed data is empty");
        }
        let creation_date = map.get::<i32, dcbor::Date>(2);
        let name = map.get::<i32, String>(3);
        let note = map.get::<i32, String>(4);
        Self::new_opt(data, name, note, creation_date)
    }
}

impl UREncodable for Seed { }

impl URDecodable for Seed { }

impl URCodable for Seed { }
