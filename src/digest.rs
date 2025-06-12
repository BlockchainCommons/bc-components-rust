use std::borrow::Cow;

use anyhow::{Result, bail};
use bc_crypto::hash::sha256;
use dcbor::prelude::*;

use crate::{digest_provider::DigestProvider, tags};

/// A cryptographically secure digest, implemented with SHA-256.
///
/// A `Digest` represents the cryptographic hash of some data. In this
/// implementation, SHA-256 is used, which produces a 32-byte hash value.
/// Digests are used throughout the crate for data verification and as unique
/// identifiers derived from data.
///
/// # CBOR Serialization
///
/// `Digest` implements the `CBORTaggedCodable` trait, which means it can be
/// serialized to and deserialized from CBOR with a specific tag. The tag used
/// is `TAG_DIGEST` defined in the `tags` module.
///
/// # UR Serialization
///
/// When serialized as a Uniform Resource (UR), a `Digest` is represented as a
/// binary blob with the type "digest".
///
/// # Examples
///
/// Creating a digest from data:
///
/// ```
/// use bc_components::Digest;
///
/// // Create a digest from a string
/// let data = "hello world";
/// let digest = Digest::from_image(data.as_bytes());
///
/// // Validate that the digest matches the original data
/// assert!(digest.validate(data.as_bytes()));
/// ```
///
/// Creating and using a digest with hexadecimal representation:
///
/// ```
/// use bc_components::Digest;
///
/// // Create a digest from a hex string
/// let hex_string =
///     "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
/// let digest = Digest::from_hex(hex_string);
///
/// // Retrieve the digest as hex
/// assert_eq!(digest.hex(), hex_string);
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest([u8; Self::DIGEST_SIZE]);

impl Digest {
    pub const DIGEST_SIZE: usize = 32;

    /// Create a new digest from data.
    pub fn from_data(data: [u8; Self::DIGEST_SIZE]) -> Self { Self(data) }

    /// Create a new digest from data.
    ///
    /// Returns `None` if the data is not the correct length.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::DIGEST_SIZE {
            bail!("Invalid digest size");
        }
        let mut arr = [0u8; Self::DIGEST_SIZE];
        arr.copy_from_slice(data.as_ref());
        Ok(Self::from_data(arr))
    }

    /// Create a new digest from the given image.
    ///
    /// The image is hashed with SHA-256.
    pub fn from_image(image: impl AsRef<[u8]>) -> Self {
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
    pub fn data(&self) -> &[u8; Self::DIGEST_SIZE] { self.into() }

    /// Get the digest as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Validate the digest against the given image.
    ///
    /// The image is hashed with SHA-256 and compared to the digest.
    /// Returns `true` if the digest matches the image.
    pub fn validate(&self, image: impl AsRef<[u8]>) -> bool {
        self == &Self::from_image(image)
    }

    /// Create a new digest from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn hex(&self) -> String { hex::encode(self.0) }

    /// The first four bytes of the digest as a hexadecimal string.
    pub fn short_description(&self) -> String { hex::encode(&self.0[0..4]) }

    /// Validate the given data against the digest, if any.
    ///
    /// Returns `true` if the digest is `None` or if the digest matches the
    /// image's digest. Returns `false` if the digest does not match the
    /// image's digest.
    pub fn validate_opt(
        image: impl AsRef<[u8]>,
        digest: Option<&Digest>,
    ) -> bool {
        match digest {
            Some(digest) => digest.validate(image),
            None => true,
        }
    }
}

/// Allows accessing the underlying data as a fixed-size byte array reference.
impl<'a> From<&'a Digest> for &'a [u8; Digest::DIGEST_SIZE] {
    fn from(value: &'a Digest) -> Self { &value.0 }
}

/// Allows accessing the underlying data as a byte slice reference.
impl<'a> From<&'a Digest> for &'a [u8] {
    fn from(value: &'a Digest) -> Self { &value.0 }
}

/// Allows using a Digest as a reference to a byte slice.
impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Provides a self-reference, enabling API consistency with other types.
impl AsRef<Digest> for Digest {
    fn as_ref(&self) -> &Digest { self }
}

/// Enables partial ordering of Digests by comparing their underlying bytes.
impl std::cmp::PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

/// Enables total ordering of Digests by comparing their underlying bytes
/// lexicographically.
impl std::cmp::Ord for Digest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.0.cmp(&other.0) }
}

/// Implements DigestProvider to return itself without copying, as a Digest is
/// already a digest.
impl DigestProvider for Digest {
    fn digest(&self) -> Cow<'_, Digest> { Cow::Borrowed(self) }
}

/// Provides a debug representation showing the digest's hexadecimal value.
impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

/// Provides a string representation showing the digest's hexadecimal value.
impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

/// Identifies the CBOR tags used for Digest serialization.
impl CBORTagged for Digest {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_DIGEST]) }
}

/// Enables conversion of a Digest into a tagged CBOR value.
impl From<Digest> for CBOR {
    fn from(value: Digest) -> Self { value.tagged_cbor() }
}

/// Defines how a Digest is encoded as CBOR (as a byte string).
impl CBORTaggedEncodable for Digest {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.0) }
}

/// Enables conversion from CBOR to Digest, with proper error handling.
impl TryFrom<CBOR> for Digest {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Defines how a Digest is decoded from CBOR.
impl CBORTaggedDecodable for Digest {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Ok(Self::from_data_ref(data)?)
    }
}

/// Enables cloning a Digest from a reference using From trait.
impl From<&Digest> for Digest {
    fn from(digest: &Digest) -> Self { digest.clone() }
}

/// Converts a Digest into a `Vec<u8>` containing the digest bytes.
impl From<Digest> for Vec<u8> {
    fn from(digest: Digest) -> Self { digest.0.to_vec() }
}

/// Converts a Digest reference into a `Vec<u8>` containing the digest bytes.
impl From<&Digest> for Vec<u8> {
    fn from(digest: &Digest) -> Self { digest.0.to_vec() }
}

#[cfg(test)]
mod tests {
    use bc_ur::prelude::*;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_digest() {
        let data = "hello world";
        let digest = Digest::from_image(data.as_bytes());
        assert_eq!(digest.data().len(), Digest::DIGEST_SIZE);
        assert_eq!(*digest.data(), sha256(data.as_bytes()));
        assert_eq!(
            *digest.data(),
            hex!(
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            )
        );
    }

    #[test]
    fn test_digest_from_hex() {
        let digest = Digest::from_hex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        );
        assert_eq!(digest.data().len(), Digest::DIGEST_SIZE);
        assert_eq!(*digest.data(), sha256("hello world".as_bytes()));
        assert_eq!(
            *digest.data(),
            hex!(
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            )
        );
    }

    #[test]
    fn test_ur() {
        crate::register_tags();
        let data = "hello world";
        let digest = Digest::from_image(data.as_bytes());
        let ur_string = digest.ur_string();
        let expected_ur_string = "ur:digest/hdcxrhgtdirhmugtfmayondmgmtstnkipyzssslrwsvlkngulawymhloylpsvowssnwlamnlatrs";
        assert_eq!(ur_string, expected_ur_string);
        let digest2 = Digest::from_ur_string(&ur_string).unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_digest_equality() {
        let digest1 = Digest::from_hex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        );
        let digest2 = Digest::from_hex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        );
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_digest_inequality() {
        let digest1 = Digest::from_hex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        );
        let digest2 = Digest::from_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
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
