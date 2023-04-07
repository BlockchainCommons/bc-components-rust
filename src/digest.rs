use bc_crypto::sha256;
use crate::{data_provider::DataProvider, digest_provider::DigestProvider};

/// A cryptographically secure digest.
///
/// Implemented with SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Digest {
    data: Vec<u8>,
}

impl Digest {
    /// The default digest length.
    pub const DEFAULT_DIGEST_LENGTH: usize = 32;

    /// Create a new digest from the given data.
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: sha256(data).to_vec(),
        }
    }

    /// Create a new digest from the given data.
    pub fn new_from_data_provider(data: &dyn DataProvider) -> Self {
        Self::new(&data.provided_data())
    }

    /// Optinally create a new digest from the given data.
    pub fn new_from_data_provider_opt(
        data: &dyn DataProvider,
        include_digest: bool,
    ) -> Option<Self> {
        if include_digest {
            Some(Self::new_from_data_provider(data))
        } else {
            None
        }
    }

    /// Create a new digest from the given raw value.
    pub fn new_from_raw_value(raw_value: &[u8], digest_length: usize) -> Option<Self> {
        if raw_value.len() == digest_length {
            Some(Self {
                data: raw_value.to_vec(),
            })
        } else {
            None
        }
    }

    /// Get the raw value of the digest.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Validate the given data against the digest.
    pub fn validate(&self, data: &dyn DataProvider) -> bool {
        self == &Self::new_from_data_provider(data)
    }

    /// Create a new digest from the given hexadecimal string.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::new_from_raw_value(&hex::decode(hex.as_ref()).unwrap(), Self::DEFAULT_DIGEST_LENGTH).unwrap()
    }

    /// The wrapped data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(&self.data)
    }

    pub fn short_description(&self) -> String {
        hex::encode(&self.data[0..4])
    }
}

impl std::cmp::PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.data.cmp(&other.data))
    }
}

impl DataProvider for Digest {
    fn provided_data(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl DigestProvider for Digest {
    fn digest(&self) -> Digest {
        self.clone()
    }
}

/// Validate the given data against the digest, if any.
pub fn validate_opt(data: &dyn DataProvider, digest: Option<&Digest>) -> bool {
    match digest {
        Some(digest) => digest.validate(data),
        None => true,
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", hex::encode(&self.data))
    }
}

pub fn concat_digests(lhs: &Digest, rhs: &Digest) -> Vec<u8> {
    let mut data = lhs.data.clone();
    data.extend_from_slice(&rhs.data);
    data
}

pub fn concat_data_with_digest(lhs: &[u8], rhs: &Digest) -> Vec<u8> {
    let mut data = lhs.to_vec();
    data.extend_from_slice(&rhs.data);
    data
}

impl From<&[u8]> for Digest {
    fn from(data: &[u8]) -> Self {
        Self::new(data)
    }
}

impl From<&str> for Digest {
    fn from(data: &str) -> Self {
        Self::new(data.as_bytes())
    }
}

impl From<&String> for Digest {
    fn from(data: &String) -> Self {
        Self::new(data.as_bytes())
    }
}

impl From<&Digest> for Digest {
    fn from(digest: &Digest) -> Self {
        digest.clone()
    }
}

impl From<Digest> for Vec<u8> {
    fn from(digest: Digest) -> Self {
        digest.data
    }
}

impl From<&Digest> for Vec<u8> {
    fn from(digest: &Digest) -> Self {
        digest.data.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest() {
        let data = "hello world";
        let digest = Digest::new(data.as_bytes());
        assert_eq!(digest.data.len(), Digest::DEFAULT_DIGEST_LENGTH);
        assert_eq!(digest.data(), sha256(data.as_bytes()));
        assert_eq!(digest.data(), hex_literal::hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    }

    #[test]
    fn test_digest_from_hex() {
        let digest = Digest::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(digest.data.len(), Digest::DEFAULT_DIGEST_LENGTH);
        assert_eq!(digest.data(), sha256("hello world".as_bytes()));
        assert_eq!(digest.data(), hex_literal::hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    }
}
