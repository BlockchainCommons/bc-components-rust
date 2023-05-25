use std::rc::Rc;
use bc_crypto::fill_random_data;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes, CBORError};
use crate::tags_registry;

 #[derive(Clone, Debug, Eq, PartialEq)]
 pub struct Nonce ([u8; Self::NONCE_LENGTH]);

impl Nonce {
    pub const NONCE_LENGTH: usize = 12;

    /// Create a new random nonce.
    pub fn new() -> Self {
        let mut data = [0u8; Self::NONCE_LENGTH];
        fill_random_data(&mut data);
        Self(data)
    }

    /// Create a new nonce from data.
    pub fn from_data(data: [u8; Self::NONCE_LENGTH]) -> Self {
        Self(data)
    }

    /// Create a new nonce from data.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::NONCE_LENGTH {
            return None;
        }
        let mut arr = [0u8; Self::NONCE_LENGTH];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Get the data of the nonce.
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    /// Create a new nonce from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 24 hexadecimal digits.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
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

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CBORTagged for Nonce {
    const CBOR_TAG: Tag = tags_registry::NONCE;
}

impl CBOREncodable for Nonce {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Nonce {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.data()).cbor()
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
        let instance = Self::from_data_ref(data).ok_or(CBORError::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({})", hex::encode(self.0))
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
        let nonce = Nonce::from_data(nonce_raw);
        assert_eq!(nonce.data(), &nonce_raw);
    }

    #[test]
    fn test_nonce_from_raw_data() {
        let raw_data = vec![0u8; Nonce::NONCE_LENGTH];
        let nonce = Nonce::from_data_ref(&raw_data).unwrap();
        assert_eq!(nonce.data(), &raw_data[..]);
    }

    #[test]
    fn test_nonce_length() {
        let raw_data = vec![0u8; Nonce::NONCE_LENGTH + 1];
        let nonce = Nonce::from_data_ref(&raw_data);
        assert_eq!(nonce, None);
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
        let cbor = nonce.cbor();
        let decoded_nonce = Nonce::from_cbor(&cbor).unwrap();
        assert_eq!(nonce, *decoded_nonce);
    }
}
