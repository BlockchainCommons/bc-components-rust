use std::borrow::Cow;

use bc_ur::prelude::*;

use crate::{Digest, Error, Result, digest_provider::DigestProvider, tags};

/// Implementers of this trait provide a globally unique reference to
/// themselves.
///
/// The `ReferenceProvider` trait is used to create a unique, cryptographic
/// reference to an object. This is particularly useful for distributed systems
/// where objects need to be uniquely identified across networks or storage
/// systems.
///
/// The reference is derived from a cryptographic digest of the object's
/// serialized form, ensuring that the reference uniquely identifies the
/// object's contents.
pub trait ReferenceProvider {
    /// Returns a cryptographic reference that uniquely identifies this object.
    ///
    /// The reference is derived from a digest of the object's serialized form,
    /// ensuring that it uniquely identifies the object's contents.
    fn reference(&self) -> Reference;

    /// Returns the reference data as a hexadecimal string.
    ///
    /// This is a convenience method that returns the full 32-byte reference
    /// as a 64-character hexadecimal string.
    fn ref_hex(&self) -> String { self.reference().ref_hex() }

    /// Returns the first four bytes of the reference.
    ///
    /// This is a convenience method for when a shorter, more user-friendly
    /// representation is needed, such as for display or comparison purposes.
    fn ref_data_short(&self) -> [u8; 4] { self.reference().ref_data_short() }

    /// Returns the first four bytes of the reference as a hexadecimal string.
    ///
    /// This produces an 8-character string that is useful for display purposes,
    /// such as in debug output or logs.
    fn ref_hex_short(&self) -> String { self.reference().ref_hex_short() }

    /// Returns the first four bytes of the reference as upper-case ByteWords.
    ///
    /// ByteWords is a human-readable encoding format that uses common English
    /// words to represent binary data, making it easier to communicate
    /// verbally or in text.
    ///
    /// # Parameters
    ///
    /// * `prefix` - An optional prefix to add before the ByteWords
    ///   representation
    fn ref_bytewords(&self, prefix: Option<&str>) -> String {
        self.reference().bytewords_identifier(prefix)
    }

    /// Returns the first four bytes of the reference as Bytemoji.
    ///
    /// Bytemoji is an emoji-based encoding that represents binary data using
    /// emoji characters, which can be more visually distinctive and memorable.
    ///
    /// # Parameters
    ///
    /// * `prefix` - An optional prefix to add before the Bytemoji
    ///   representation
    fn ref_bytemoji(&self, prefix: Option<&str>) -> String {
        self.reference().bytemoji_identifier(prefix)
    }
}

/// A globally unique reference to a globally unique object.
///
/// `Reference` provides a cryptographically secure way to uniquely identify
/// objects based on their content. It is a fixed-size (32 bytes) identifier,
/// typically derived from the SHA-256 hash of the object's serialized form.
///
/// References are useful in distributed systems for:
/// - Unique identification of objects across networks
/// - Verification that an object hasn't been modified
/// - Content-addressable storage systems
/// - Linking between objects in a content-addressed way
///
/// A `Reference` can be displayed in various formats, including hexadecimal,
/// ByteWords (a human-readable partial hash as words), and Bytemoji (a
/// human-readable partial hash based on emojis).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Reference([u8; Self::REFERENCE_SIZE]);

impl Reference {
    pub const REFERENCE_SIZE: usize = 32;

    /// Create a new reference from data.
    pub fn from_data(data: [u8; Self::REFERENCE_SIZE]) -> Self { Self(data) }

    /// Create a new reference from data.
    ///
    /// Returns `None` if the data is not the correct length.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::REFERENCE_SIZE {
            return Err(Error::invalid_size(
                "reference",
                Self::REFERENCE_SIZE,
                data.len(),
            ));
        }
        let mut arr = [0u8; Self::REFERENCE_SIZE];
        arr.copy_from_slice(data.as_ref());
        Ok(Self::from_data(arr))
    }

    /// Create a new reference from the given digest.
    pub fn from_digest(digest: Digest) -> Self {
        Self::from_data(*digest.data())
    }

    /// Get the data of the reference.
    pub fn data(&self) -> &[u8; Self::REFERENCE_SIZE] { self.into() }

    /// Get the data of the reference as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Create a new reference from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn ref_hex(&self) -> String { hex::encode(self.0) }

    /// The first four bytes of the reference
    pub fn ref_data_short(&self) -> [u8; 4] { self.0[0..4].try_into().unwrap() }

    /// The first four bytes of the reference as a hexadecimal string.
    pub fn ref_hex_short(&self) -> String { hex::encode(self.ref_data_short()) }

    /// The first four bytes of the XID as upper-case ByteWords.
    pub fn bytewords_identifier(&self, prefix: Option<&str>) -> String {
        let s = bytewords::identifier(&self.ref_data_short()).to_uppercase();
        if let Some(prefix) = prefix {
            format!("{prefix} {s}")
        } else {
            s
        }
    }

    /// The first four bytes of the XID as Bytemoji.
    pub fn bytemoji_identifier(&self, prefix: Option<&str>) -> String {
        let s =
            bytewords::bytemoji_identifier(&self.0[..4].try_into().unwrap())
                .to_uppercase();
        if let Some(prefix) = prefix {
            format!("{prefix} {s}")
        } else {
            s
        }
    }
}

/// Implement the `ReferenceProvider` trait for `Reference`.
///
/// Yes, this creates a Reference to a Reference.
impl ReferenceProvider for Reference {
    fn reference(&self) -> Reference {
        Reference::from_digest(self.digest().into_owned())
    }
}

impl<'a> From<&'a Reference> for &'a [u8; Reference::REFERENCE_SIZE] {
    fn from(value: &'a Reference) -> Self { &value.0 }
}

impl<'a> From<&'a Reference> for &'a [u8] {
    fn from(value: &'a Reference) -> Self { &value.0 }
}

impl AsRef<[u8]> for Reference {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsRef<Reference> for Reference {
    fn as_ref(&self) -> &Reference { self }
}

impl std::cmp::PartialOrd for Reference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl std::cmp::Ord for Reference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.0.cmp(&other.0) }
}

impl DigestProvider for Reference {
    fn digest(&self) -> Cow<'_, Digest> {
        Cow::Owned(Digest::from_image(self.tagged_cbor().to_cbor_data()))
    }
}

impl std::fmt::Debug for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reference({})", self.ref_hex())
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reference({})", self.ref_hex_short())
    }
}

impl CBORTagged for Reference {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_REFERENCE]) }
}

impl From<Reference> for CBOR {
    fn from(value: Reference) -> Self { value.tagged_cbor() }
}

impl CBORTaggedEncodable for Reference {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.0) }
}

impl TryFrom<CBOR> for Reference {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Reference {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Ok(Self::from_data_ref(data)?)
    }
}

// Convert from an instance reference to an instance.
impl From<&Reference> for Reference {
    fn from(digest: &Reference) -> Self { digest.clone() }
}

// Convert from a byte vector to an instance.
impl From<Reference> for Vec<u8> {
    fn from(digest: Reference) -> Self { digest.0.to_vec() }
}

// Convert a reference to an instance to a byte vector.
impl From<&Reference> for Vec<u8> {
    fn from(digest: &Reference) -> Self { digest.0.to_vec() }
}
