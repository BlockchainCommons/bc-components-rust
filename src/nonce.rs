use std::rc::Rc;
use bc_rand::fill_random_data;
use bc_ur::prelude::*;
use crate::tags;
use anyhow::{ bail, Error, Result };

/// A random nonce ("number used once").
#[derive(Clone, Eq, PartialEq)]
pub struct Nonce([u8; Self::NONCE_SIZE]);

impl Nonce {
    pub const NONCE_SIZE: usize = 12;

    /// Create a new random nonce.
    pub fn new() -> Self {
        let mut data = [0u8; Self::NONCE_SIZE];
        fill_random_data(&mut data);
        Self(data)
    }

    /// Restores a nonce from data.
    pub const fn from_data(data: [u8; Self::NONCE_SIZE]) -> Self {
        Self(data)
    }

    /// Restores a nonce from data.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::NONCE_SIZE {
            bail!("Invalid nonce size");
        }
        let mut arr = [0u8; Self::NONCE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get the data of the nonce.
    pub fn data(&self) -> &[u8; Self::NONCE_SIZE] {
        self.into()
    }

    /// Create a new nonce from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 24 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Rc<Nonce>> for Nonce {
    fn from(value: Rc<Nonce>) -> Self {
        value.as_ref().clone()
    }
}

impl<'a> From<&'a Nonce> for &'a [u8; Nonce::NONCE_SIZE] {
    fn from(value: &'a Nonce) -> Self {
        &value.0
    }
}

impl AsRef<Nonce> for Nonce {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl CBORTagged for Nonce {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::NONCE]
    }
}

impl From<Nonce> for CBOR {
    fn from(value: Nonce) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Nonce {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.data())
    }
}

impl TryFrom<CBOR> for Nonce {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Nonce {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        Self::from_data_ref(data)
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({})", self.hex())
    }
}

// Convert from a reference to a byte vector to a Nonce.
impl From<&Nonce> for Nonce {
    fn from(nonce: &Nonce) -> Self {
        nonce.clone()
    }
}

// Convert from a byte vector to a Nonce.
impl From<Nonce> for Vec<u8> {
    fn from(nonce: Nonce) -> Self {
        nonce.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a Nonce.
impl From<&Nonce> for Vec<u8> {
    fn from(nonce: &Nonce) -> Self {
        nonce.0.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::Nonce;
    use dcbor::prelude::*;

    #[test]
    fn test_nonce_raw() {
        let nonce_raw = [0u8; Nonce::NONCE_SIZE];
        let nonce = Nonce::from_data(nonce_raw);
        assert_eq!(nonce.data(), &nonce_raw);
    }

    #[test]
    fn test_nonce_from_raw_data() {
        let raw_data = vec![0u8; Nonce::NONCE_SIZE];
        let nonce = Nonce::from_data_ref(&raw_data).unwrap();
        assert_eq!(nonce.data(), &raw_data[..]);
    }

    #[test]
    fn test_nonce_size() {
        let raw_data = vec![0u8; Nonce::NONCE_SIZE + 1];
        let nonce = Nonce::from_data_ref(raw_data);
        assert!(nonce.is_err());
    }

    #[test]
    fn test_nonce_new() {
        let nonce1 = Nonce::new();
        let nonce2 = Nonce::new();
        assert_ne!(nonce1.data(), nonce2.data());
    }

    #[test]
    fn test_nonce_hex_roundtrip() {
        let nonce = Nonce::new();
        let hex_string = nonce.hex();
        let nonce_from_hex = Nonce::from_hex(hex_string);
        assert_eq!(nonce, nonce_from_hex);
    }

    #[test]
    fn test_nonce_cbor_roundtrip() {
        let nonce = Nonce::new();
        let cbor: CBOR = nonce.clone().into();
        let decoded_nonce = Nonce::try_from(cbor).unwrap();
        assert_eq!(nonce, decoded_nonce);
    }
}
