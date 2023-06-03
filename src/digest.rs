use std::{rc::Rc, borrow::Cow};
use bc_crypto::hash::sha256;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable, Bytes};
use bc_ur::{UREncodable, URDecodable, URCodable};
use crate::{digest_provider::DigestProvider, tags_registry};

/// A cryptographically secure digest.
///
/// Implemented with SHA-256.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest([u8; Self::DIGEST_SIZE]);

impl Digest {
    pub const DIGEST_SIZE: usize = 32;

    /// Create a new digest from data.
    pub fn from_data(data: [u8; Self::DIGEST_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new digest from data.
    ///
    /// Returns `None` if the data is not the correct length.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::DIGEST_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::DIGEST_SIZE];
        arr.copy_from_slice(data.as_ref());
        Some(Self::from_data(arr))
    }

    /// Create a new digest from the given image.
    ///
    /// The image is hashed with SHA-256.
    pub fn from_image<T>(image: &T) -> Self where T: AsRef<[u8]> {
        Self::from_data(sha256(image.as_ref()))
    }

    /// Create a new digest from an array of data items.
    ///
    /// The image parts are concatenated and hashed with SHA-256.
    pub fn from_image_parts(image_parts: &[&[u8]]) -> Self {
        let mut buf = Vec::new();
        for part in image_parts {
            buf.extend_from_slice(part);
        }
        Self::from_image(&buf)
    }

    /// Create a new digest from an array of Digests.
    ///
    /// The image parts are concatenated and hashed with SHA-256.
    pub fn from_digests(digests: &[Digest]) -> Self {
        let mut buf = Vec::new();
        for digest in digests {
            buf.extend_from_slice(digest.data());
        }
        Self::from_image(&buf)
    }

    /// Get the data of the digest.
    pub fn data(&self) -> &[u8; 32] {
        self.into()
    }

    /// Validate the digest against the given image.
    ///
    /// The image is hashed with SHA-256 and compared to the digest.
    /// Returns `true` if the digest matches the image.
    pub fn validate<T>(&self, image: &T) -> bool where T: AsRef<[u8]> {
        self == &Self::from_image(image)
    }

    /// Create a new digest from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The first four bytes of the digest as a hexadecimal string.
    pub fn short_description(&self) -> String {
        hex::encode(&self.0[0..4])
    }

    /// Validate the given data against the digest, if any.
    ///
    /// Returns `true` if the digest is `None` or if the digest matches the image's digest.
    /// Returns `false` if the digest does not match the image's digest.
    pub fn validate_opt<T>(image: &T, digest: Option<&Digest>) -> bool where T: AsRef<[u8]> {
        match digest {
            Some(digest) => digest.validate(image),
            None => true,
        }
    }
}

impl<'a> From<&'a Digest> for &'a [u8; Digest::DIGEST_SIZE] {
    fn from(value: &'a Digest) -> Self {
        &value.0
    }
}

impl<'a> From<&'a Digest> for &'a [u8] {
    fn from(value: &'a Digest) -> Self {
        &value.0
    }
}

impl std::cmp::PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl std::cmp::Ord for Digest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl DigestProvider for Digest {
    fn digest(&self) -> Cow<Digest> {
        Cow::Borrowed(self)
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

impl CBORTagged for Digest {
    const CBOR_TAG: Tag = tags_registry::DIGEST;
}

impl CBOREncodable for Digest {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Digest {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(self.0).cbor()
    }
}

impl UREncodable for Digest { }

impl CBORDecodable for Digest {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Digest {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(cbor)?;
        let instance = Self::from_data_ref(&bytes.data()).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}

impl URDecodable for Digest { }

impl URCodable for Digest { }

// Convert from a reference to a byte vector to an instance.
impl From<&Digest> for Digest {
    fn from(digest: &Digest) -> Self {
        digest.clone()
    }
}

// Convert from a byte vector to an instance.
impl From<Digest> for Vec<u8> {
    fn from(digest: Digest) -> Self {
        digest.0.to_vec()
    }
}

// Convert a reference to an instance to a byte vector.
impl From<&Digest> for Vec<u8> {
    fn from(digest: &Digest) -> Self {
        digest.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_digest() {
        let data = "hello world";
        let digest = Digest::from_image(&data.as_bytes());
        assert_eq!(digest.data().len(), Digest::DIGEST_SIZE);
        assert_eq!(*digest.data(), sha256(data.as_bytes()));
        assert_eq!(*digest.data(), hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    }

    #[test]
    fn test_digest_from_hex() {
        let digest = Digest::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(digest.data().len(), Digest::DIGEST_SIZE);
        assert_eq!(*digest.data(), sha256("hello world".as_bytes()));
        assert_eq!(*digest.data(), hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    }

    #[test]
    fn test_ur() {
        let data = "hello world";
        let digest = Digest::from_image(&data.as_bytes());
        let ur_string = digest.ur_string();
        let expected_ur_string = "ur:digest/hdcxrhgtdirhmugtfmayondmgmtstnkipyzssslrwsvlkngulawymhloylpsvowssnwlamnlatrs";
        assert_eq!(ur_string, expected_ur_string);
        let digest2 = Digest::from_ur_string(&ur_string).unwrap();
        assert_eq!(digest, *digest2);
    }

    #[test]
    fn test_digest_equality() {
        let digest1 = Digest::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let digest2 = Digest::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_digest_inequality() {
        let digest1 = Digest::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let digest2 = Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_ne!(digest1, digest2);
    }

    #[test]
    #[should_panic]
    fn test_invalid_hex_string() {
        let _ = Digest::from_hex("invalid_hex_string");
    }

    #[test]
    #[should_panic]
    fn test_new_from_invalid_ur_string() {
        let invalid_ur = "ur:not_digest/invalid";
        let _ = Digest::from_ur_string(invalid_ur).unwrap();
    }
}
