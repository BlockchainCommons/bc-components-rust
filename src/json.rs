use bc_ur::prelude::*;

use crate::tags;

/// A CBOR-tagged container for UTF-8 JSON text.
///
/// The `JSON` type wraps UTF-8 JSON text as a CBOR byte string with tag 262.
/// This allows JSON data to be embedded within CBOR structures while
/// maintaining type information through the tag.
///
/// This implementation does not validate that the contained data is well-formed
/// JSON. It simply provides a type-safe wrapper around byte data that is
/// intended to contain JSON text.
///
/// # CBOR Serialization
///
/// `JSON` implements the `CBORTaggedCodable` trait, which means it can be
/// serialized to and deserialized from CBOR with tag 262 (`TAG_JSON`).
///
/// # Examples
///
/// Creating JSON from a string:
///
/// ```
/// use bc_components::JSON;
///
/// let json = JSON::from_string(r#"{"key": "value"}"#);
/// assert_eq!(json.as_str(), r#"{"key": "value"}"#);
/// ```
///
/// Creating JSON from bytes:
///
/// ```
/// use bc_components::JSON;
///
/// let json = JSON::from_data(b"[1, 2, 3]");
/// assert_eq!(json.len(), 9);
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct JSON(Vec<u8>);

impl JSON {
    /// Return the length of the JSON data in bytes.
    pub fn len(&self) -> usize { self.0.len() }

    /// Return true if the JSON data is empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Create a new JSON instance from byte data.
    pub fn from_data(data: impl AsRef<[u8]>) -> Self {
        Self(data.as_ref().to_vec())
    }

    /// Create a new JSON instance from a string.
    pub fn from_string(s: impl AsRef<str>) -> Self {
        Self::from_data(s.as_ref().as_bytes())
    }

    /// Return the data as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Return the data as a UTF-8 string slice.
    ///
    /// # Panics
    ///
    /// Panics if the data is not valid UTF-8.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("Invalid UTF-8 in JSON data")
    }

    /// Create a new JSON instance from a hexadecimal string.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data(hex::decode(hex.as_ref()).unwrap())
    }

    /// Return the data as a hexadecimal string.
    pub fn hex(&self) -> String { hex::encode(self.as_bytes()) }
}

/// Allows accessing the underlying data as a byte slice reference.
impl<'a> From<&'a JSON> for &'a [u8] {
    fn from(value: &'a JSON) -> Self { value.as_bytes() }
}

/// Allows using a JSON as a reference to a byte slice.
impl AsRef<[u8]> for JSON {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Provides a self-reference, enabling API consistency with other types.
impl AsRef<JSON> for JSON {
    fn as_ref(&self) -> &JSON { self }
}

/// Identifies the CBOR tags used for JSON serialization.
impl CBORTagged for JSON {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_JSON]) }
}

/// Enables conversion of JSON into a tagged CBOR value.
impl From<JSON> for CBOR {
    fn from(value: JSON) -> Self { value.tagged_cbor() }
}

/// Defines how JSON is encoded as CBOR (as a byte string).
impl CBORTaggedEncodable for JSON {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.as_bytes()) }
}

/// Enables conversion from CBOR to JSON, with proper error handling.
impl TryFrom<CBOR> for JSON {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Defines how JSON is decoded from CBOR.
impl CBORTaggedDecodable for JSON {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        let instance = Self::from_data(data);
        Ok(instance)
    }
}

/// Provides a debug representation showing the JSON data as a string.
impl std::fmt::Debug for JSON {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON({})", self.as_str())
    }
}

/// Enables cloning a JSON from a reference using From trait.
impl From<&JSON> for JSON {
    fn from(json: &JSON) -> Self { json.clone() }
}

/// Converts JSON into a `Vec<u8>` containing the JSON bytes.
impl From<JSON> for Vec<u8> {
    fn from(json: JSON) -> Self { json.0.to_vec() }
}

/// Converts a JSON reference into a `Vec<u8>` containing the JSON bytes.
impl From<&JSON> for Vec<u8> {
    fn from(json: &JSON) -> Self { json.0.to_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_creation() {
        let json = JSON::from_string(r#"{"key": "value"}"#);
        assert_eq!(json.as_str(), r#"{"key": "value"}"#);
        assert_eq!(json.len(), 16);
        assert!(!json.is_empty());
    }

    #[test]
    fn test_json_from_bytes() {
        let data = b"[1, 2, 3]";
        let json = JSON::from_data(data);
        assert_eq!(json.as_bytes(), data);
        assert_eq!(json.as_str(), "[1, 2, 3]");
    }

    #[test]
    fn test_json_empty() {
        let json = JSON::from_string("");
        assert!(json.is_empty());
        assert_eq!(json.len(), 0);
    }

    #[test]
    fn test_json_cbor_roundtrip() {
        let json = JSON::from_string(r#"{"name":"Alice","age":30}"#);
        let cbor: CBOR = json.clone().into();
        let json2: JSON = cbor.try_into().unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_json_hex() {
        let json = JSON::from_string("test");
        let hex = json.hex();
        let json2 = JSON::from_hex(hex);
        assert_eq!(json, json2);
    }

    #[test]
    fn test_json_debug() {
        let json = JSON::from_string(r#"{"test":true}"#);
        let debug = format!("{:?}", json);
        assert_eq!(debug, r#"JSON({"test":true})"#);
    }

    #[test]
    fn test_json_clone() {
        let json = JSON::from_string("original");
        let json2 = json.clone();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_json_into_vec() {
        let json = JSON::from_string("data");
        let vec: Vec<u8> = json.into();
        assert_eq!(vec, b"data");
    }
}
