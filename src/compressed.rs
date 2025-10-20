use std::{borrow::Cow, fmt::Formatter};

use bc_crypto::hash::crc32;
use bc_ur::prelude::*;
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec};

use crate::{DigestProvider, Error, Result, digest::Digest, tags};

/// A compressed binary object with integrity verification.
///
/// `Compressed` provides a way to efficiently store and transmit binary data
/// using the DEFLATE compression algorithm. It includes built-in integrity
/// verification through a CRC32 checksum and optional cryptographic digest.
///
/// The compression is implemented using the raw DEFLATE format as described in
/// [IETF RFC 1951](https://www.ietf.org/rfc/rfc1951.txt) with the following
/// configuration equivalent to:
///
/// `deflateInit2(zstream, 5, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)`
///
/// Features:
/// - Automatic compression with configurable compression level
/// - Integrity verification via CRC32 checksum
/// - Optional cryptographic digest for content identification
/// - Smart behavior for small data (stores decompressed if compression would
///   increase size)
/// - CBOR serialization/deserialization support
#[derive(Clone, Eq, PartialEq)]
pub struct Compressed {
    /// CRC32 checksum of the decompressed data for integrity verification
    checksum: u32,
    /// Size of the original decompressed data in bytes
    decompressed_size: usize,
    /// The compressed data (or original data if compression is ineffective)
    compressed_data: Vec<u8>,
    /// Optional cryptographic digest of the content
    digest: Option<Digest>,
}

impl Compressed {
    /// Creates a new `Compressed` object with the specified parameters.
    ///
    /// This is a low-level constructor that allows direct creation of a
    /// `Compressed` object without performing compression. It's primarily
    /// intended for deserialization or when working with pre-compressed
    /// data.
    ///
    /// # Parameters
    ///
    /// * `checksum` - CRC32 checksum of the decompressed data
    /// * `decompressed_size` - Size of the original decompressed data in bytes
    /// * `compressed_data` - The compressed data bytes
    /// * `digest` - Optional cryptographic digest of the content
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Compressed` object if successful,
    /// or an error if the parameters are invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if the compressed data is larger than the decompressed
    /// size, which would indicate a logical inconsistency.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::Compressed;
    /// use bc_crypto::hash::crc32;
    ///
    /// let data = b"hello world";
    /// let checksum = crc32(data);
    /// let decompressed_size = data.len();
    ///
    /// // In a real scenario, this would be actually compressed data
    /// let compressed_data = data.to_vec();
    ///
    /// let compressed =
    ///     Compressed::new(checksum, decompressed_size, compressed_data, None)
    ///         .unwrap();
    /// ```
    pub fn new(
        checksum: u32,
        decompressed_size: usize,
        compressed_data: Vec<u8>,
        digest: Option<Digest>,
    ) -> Result<Self> {
        if compressed_data.len() > decompressed_size {
            return Err(Error::compression(
                "compressed data is larger than decompressed size",
            ));
        }
        Ok(Self {
            checksum,
            decompressed_size,
            compressed_data,
            digest,
        })
    }

    /// Creates a new `Compressed` object by compressing the provided data.
    ///
    /// This is the primary method for creating compressed data. It
    /// automatically handles compression using the DEFLATE algorithm with a
    /// compression level of 6.
    ///
    /// If the compressed data would be larger than the original data (which can
    /// happen with small or already compressed inputs), the original data
    /// is stored instead.
    ///
    /// # Parameters
    ///
    /// * `decompressed_data` - The original data to compress
    /// * `digest` - Optional cryptographic digest of the content
    ///
    /// # Returns
    ///
    /// A new `Compressed` object containing the compressed (or original) data.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::Compressed;
    ///
    /// // Compress a string
    /// let data = "This is a longer string that should compress well with repeated patterns. \
    ///            This is a longer string that should compress well with repeated patterns.";
    /// let compressed = Compressed::from_decompressed_data(data.as_bytes(), None);
    ///
    /// // The compressed size should be smaller than the original
    /// assert!(compressed.compressed_size() < data.len());
    ///
    /// // We can recover the original data
    /// let decompressed = compressed.decompress().unwrap();
    /// assert_eq!(decompressed, data.as_bytes());
    /// ```
    pub fn from_decompressed_data(
        decompressed_data: impl AsRef<[u8]>,
        digest: Option<Digest>,
    ) -> Self {
        let decompressed_data = decompressed_data.as_ref();
        let compressed_data = compress_to_vec(decompressed_data, 6);
        let checksum = crc32(decompressed_data);
        let decompressed_size = decompressed_data.len();
        let compressed_size = compressed_data.len();
        if compressed_size != 0 && compressed_size < decompressed_size {
            Self {
                checksum,
                decompressed_size,
                compressed_data,
                digest,
            }
        } else {
            Self {
                checksum,
                decompressed_size,
                compressed_data: decompressed_data.to_vec(),
                digest,
            }
        }
    }

    /// Decompresses and returns the original decompressed data.
    ///
    /// This method performs the reverse of the compression process, restoring
    /// the original data. It also verifies the integrity of the data using the
    /// stored checksum.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decompressed data if successful,
    /// or an error if decompression fails or the checksum doesn't match.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The compressed data is corrupt and cannot be decompressed
    /// - The checksum of the decompressed data doesn't match the stored
    ///   checksum
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::Compressed;
    ///
    /// // Original data
    /// let original = b"This is some example data to compress";
    ///
    /// // Compress it
    /// let compressed = Compressed::from_decompressed_data(original, None);
    ///
    /// // Deompress to get the original data back
    /// let decompressed = compressed.decompress().unwrap();
    /// assert_eq!(decompressed, original);
    /// ```
    pub fn decompress(&self) -> Result<Vec<u8>> {
        let compressed_size = self.compressed_data.len();
        if compressed_size >= self.decompressed_size {
            return Ok(self.compressed_data.clone());
        }

        let decompressed_data = decompress_to_vec(&self.compressed_data)
            .map_err(|_| Error::compression("corrupt compressed data"))?;
        if crc32(&decompressed_data) != self.checksum {
            return Err(Error::compression(
                "compressed data checksum mismatch",
            ));
        }

        Ok(decompressed_data)
    }

    /// Returns the size of the compressed data in bytes.
    ///
    /// # Returns
    ///
    /// The size of the compressed data in bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::Compressed;
    ///
    /// let data = b"Hello world!";
    /// let compressed = Compressed::from_decompressed_data(data, None);
    ///
    /// // For small inputs like this, compression might not be effective
    /// // so the compressed_size might equal the original size
    /// println!("Compressed size: {}", compressed.compressed_size());
    /// ```
    pub fn compressed_size(&self) -> usize {
        self.compressed_data.len()
    }

    /// Returns the compression ratio of the data.
    ///
    /// The compression ratio is calculated as (compressed size) / (decompressed
    /// size), so lower values indicate better compression.
    ///
    /// # Returns
    ///
    /// A floating-point value representing the compression ratio.
    /// - Values less than 1.0 indicate effective compression
    /// - Values equal to 1.0 indicate no compression was applied
    /// - Values of NaN can occur if the decompressed size is zero
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::Compressed;
    ///
    /// // A string with a lot of repetition should compress well
    /// let data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let compressed = Compressed::from_decompressed_data(data.as_bytes(), None);
    ///
    /// // Should have a good compression ratio (much less than 1.0)
    /// let ratio = compressed.compression_ratio();
    /// assert!(ratio < 0.5);
    /// ```
    pub fn compression_ratio(&self) -> f64 {
        (self.compressed_size() as f64) / (self.decompressed_size as f64)
    }

    /// Returns a reference to the digest of the compressed data, if available.
    ///
    /// # Returns
    ///
    /// An optional reference to the `Digest` associated with this compressed
    /// data.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{Compressed, Digest};
    ///
    /// let data = b"Hello world!";
    /// let digest = Digest::from_image(data);
    /// let compressed =
    ///     Compressed::from_decompressed_data(data, Some(digest.clone()));
    ///
    /// // We can retrieve the digest we associated with the compressed data
    /// assert_eq!(compressed.digest_ref_opt(), Some(&digest));
    /// ```
    pub fn digest_ref_opt(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }

    /// Returns whether this compressed data has an associated digest.
    ///
    /// # Returns
    ///
    /// `true` if this compressed data has a digest, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{Compressed, Digest};
    ///
    /// // Create compressed data without a digest
    /// let compressed1 = Compressed::from_decompressed_data(b"Hello", None);
    /// assert!(!compressed1.has_digest());
    ///
    /// // Create compressed data with a digest
    /// let digest = Digest::from_image(b"Hello");
    /// let compressed2 =
    ///     Compressed::from_decompressed_data(b"Hello", Some(digest));
    /// assert!(compressed2.has_digest());
    /// ```
    pub fn has_digest(&self) -> bool {
        self.digest.is_some()
    }
}

/// Implementation of the `DigestProvider` trait for `Compressed`.
///
/// Allows `Compressed` objects with digests to be used with APIs that accept
/// `DigestProvider` implementations.
impl DigestProvider for Compressed {
    /// Returns the cryptographic digest associated with this compressed data.
    ///
    /// # Returns
    ///
    /// A `Cow<'_, Digest>` containing the digest.
    ///
    /// # Panics
    ///
    /// Panics if there is no digest associated with this compressed data.
    /// Use `has_digest()` or `digest_ref_opt()` to check before calling this
    /// method.
    fn digest(&self) -> Cow<'_, Digest> {
        Cow::Owned(self.digest.as_ref().unwrap().clone())
    }
}

/// Implementation of the `Debug` trait for `Compressed`.
///
/// Provides a human-readable debug representation of a `Compressed` object
/// showing its key properties: checksum, sizes, compression ratio, and digest.
impl std::fmt::Debug for Compressed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compressed(checksum: {}, size: {}/{}, ratio: {:.2}, digest: {})",
            hex::encode(self.checksum.to_be_bytes()),
            self.compressed_size(),
            self.decompressed_size,
            self.compression_ratio(),
            self.digest_ref_opt()
                .map(|d| d.short_description())
                .unwrap_or_else(|| "None".to_string())
        )
    }
}

/// Implementation of `AsRef<Compressed>` for `Compressed`.
///
/// This allows passing a `Compressed` instance to functions that take
/// `AsRef<Compressed>` parameters.
impl AsRef<Compressed> for Compressed {
    fn as_ref(&self) -> &Compressed {
        self
    }
}

/// Implementation of the `CBORTagged` trait for `Compressed`.
///
/// Defines the CBOR tag(s) used when serializing a `Compressed` object.
impl CBORTagged for Compressed {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_COMPRESSED])
    }
}

/// Conversion from `Compressed` to CBOR for serialization.
impl From<Compressed> for CBOR {
    fn from(value: Compressed) -> Self {
        value.tagged_cbor()
    }
}

/// Implementation of CBOR encoding for `Compressed`.
///
/// Defines how a `Compressed` object is serialized to untagged CBOR.
/// The format is:
/// ```text
/// [
///   checksum: uint,
///   decompressed_size: uint,
///   compressed_data: bytes,
///   digest?: Digest  // Optional
/// ]
/// ```
impl CBORTaggedEncodable for Compressed {
    fn untagged_cbor(&self) -> CBOR {
        let mut elements = vec![
            self.checksum.into(),
            self.decompressed_size.into(),
            CBOR::to_byte_string(&self.compressed_data),
        ];
        if let Some(digest) = self.digest.clone() {
            elements.push(digest.into());
        }
        CBORCase::Array(elements).into()
    }
}

/// Conversion from CBOR to `Compressed` for deserialization.
impl TryFrom<CBOR> for Compressed {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implementation of CBOR decoding for `Compressed`.
///
/// Defines how to create a `Compressed` object from untagged CBOR.
impl CBORTaggedDecodable for Compressed {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let elements = cbor.try_into_array()?;
        if elements.len() < 3 || elements.len() > 4 {
            return Err("invalid number of elements in compressed".into());
        }
        let checksum = elements[0].clone().try_into()?;
        let decompressed_size = elements[1].clone().try_into()?;
        let compressed_data = elements[2].clone().try_into_byte_string()?;
        let digest = if elements.len() == 4 {
            Some(elements[3].clone().try_into()?)
        } else {
            None
        };
        Ok(Self::new(
            checksum,
            decompressed_size,
            compressed_data,
            digest,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use crate::Compressed;

    #[test]
    fn test_1() {
        let source =
            b"Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium.";
        let compressed = Compressed::from_decompressed_data(source, None);
        assert_eq!(
            format!("{:?}", compressed),
            "Compressed(checksum: 3eeb10a0, size: 217/364, ratio: 0.60, digest: None)"
        );
        assert_eq!(compressed.decompress().unwrap(), source);
    }

    #[test]
    fn test_2() {
        let source = b"Lorem ipsum dolor sit amet consectetur adipiscing";
        let compressed = Compressed::from_decompressed_data(source, None);
        assert_eq!(
            format!("{:?}", compressed),
            "Compressed(checksum: 29db1793, size: 45/49, ratio: 0.92, digest: None)"
        );
        assert_eq!(compressed.decompress().unwrap(), source);
    }

    #[test]
    fn test_3() {
        let source = b"Lorem";
        let compressed = Compressed::from_decompressed_data(source, None);
        assert_eq!(
            format!("{:?}", compressed),
            "Compressed(checksum: 44989b39, size: 5/5, ratio: 1.00, digest: None)"
        );
        assert_eq!(compressed.decompress().unwrap(), source);
    }

    #[test]
    fn test_4() {
        let source = b"";
        let compressed = Compressed::from_decompressed_data(source, None);
        assert_eq!(
            format!("{:?}", compressed),
            "Compressed(checksum: 00000000, size: 0/0, ratio: NaN, digest: None)"
        );
        assert_eq!(compressed.decompress().unwrap(), source);
    }
}
