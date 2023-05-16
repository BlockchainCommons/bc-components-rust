use std::rc::Rc;

use bc_crypto::random_data;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes, CBORError};
use crate::tags;

 #[derive(Clone, Debug, Eq, PartialEq)]
 pub struct Nonce ([u8; Self::NONCE_LENGTH]);

impl Nonce {
    pub const NONCE_LENGTH: usize = 12;

    /// Create a new nonce from raw bytes.
    pub fn from_raw(raw: [u8; Self::NONCE_LENGTH]) -> Self {
        Self(raw)
    }

    /// Create a new nonce from raw bytes.
    pub fn from_raw_data<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let raw = data.as_ref();
        if raw.len() != Self::NONCE_LENGTH {
            return None;
        }
        let mut arr = [0u8; Self::NONCE_LENGTH];
        arr.copy_from_slice(&raw);
        Some(Self::from_raw(arr))
    }

    /// Create a new random nonce.
    pub fn new() -> Self {
        let data = random_data(Self::NONCE_LENGTH);
        Self::from_raw_data(&data).unwrap()
    }

    /// Get the raw value of the nonce.
    pub fn raw(&self) -> &[u8] {
        &self.0
    }

    /// Create a new nonce from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 24 hexadecimal digits.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_raw_data(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The raw value as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.raw())
    }
}

impl CBORTagged for Nonce {
    const CBOR_TAG: Tag = tags::NONCE;
}

impl CBOREncodable for Nonce {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Nonce {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.raw()).cbor()
    }
}

impl CBORDecodable for Nonce {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Nonce {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = Bytes::from_cbor(untagged_cbor)?;
        let data = bytes.data();
        let instance = Self::from_raw_data(data).ok_or(CBORError::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({})", hex::encode(&self.0))
    }
}

// Convert from a thing that can be referenced as an array of bytes to a Nonce.
impl<T: AsRef<[u8]>> From<T> for Nonce {
    fn from(data: T) -> Self {
        Self::from_raw_data(&data).unwrap()
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
    use dcbor::{CBOREncodable, CBORDecodable};

    #[test]
    fn test_nonce_raw() {
        let nonce_raw = [0u8; Nonce::NONCE_LENGTH];
        let nonce = Nonce::from_raw(nonce_raw);
        assert_eq!(nonce.raw(), &nonce_raw);
    }

    #[test]
    fn test_nonce_from_raw_data() {
        let raw_data = vec![0u8; Nonce::NONCE_LENGTH];
        let nonce = Nonce::from_raw_data(&raw_data).unwrap();
        assert_eq!(nonce.raw(), &raw_data[..]);
    }

    #[test]
    fn test_nonce_length() {
        let raw_data = vec![0u8; Nonce::NONCE_LENGTH + 1];
        let nonce = Nonce::from_raw_data(&raw_data);
        assert_eq!(nonce, None);
    }

    #[test]
    fn test_nonce_new() {
        let nonce1 = Nonce::new();
        let nonce2 = Nonce::new();
        assert_ne!(nonce1.raw(), nonce2.raw());
    }

    #[test]
    fn test_nonce_hex_roundtrip() {
        let nonce = Nonce::new();
        let hex_string = nonce.hex();
        let nonce_from_hex = Nonce::from_hex(&hex_string);
        assert_eq!(nonce, nonce_from_hex);
    }

    #[test]
    fn test_nonce_cbor_roundtrip() {
        let nonce = Nonce::new();
        let cbor = nonce.cbor();
        let decoded_nonce = Nonce::from_cbor(&cbor).unwrap();
        assert_eq!(nonce, *decoded_nonce);
    }
}
