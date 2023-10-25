use std::{fmt::Formatter, borrow::Cow};
use bc_ur::prelude::*;
use bc_crypto::hash::crc32;
use bytes::Bytes;
use miniz_oxide::{inflate::decompress_to_vec, deflate::compress_to_vec};
use crate::{digest::Digest, DigestProvider, tags};
use anyhow::{anyhow, bail};

/// A compressed binary object.
///
/// Implemented using the raw DEFLATE format as described in
/// [IETF RFC 1951](https://www.ietf.org/rfc/rfc1951.txt).
///
/// The following obtains the equivalent configuration of the encoder:
///
/// `deflateInit2(zstream,5,Z_DEFLATED,-15,8,Z_DEFAULT_STRATEGY)`
///
/// If the payload is too small to compress, the uncompressed payload is placed in
/// the `compressedData` field and the size of that field will be the same as the
/// `uncompressedSize` field.
#[derive(Clone, Eq, PartialEq)]
pub struct Compressed {
    checksum: u32,
    uncompressed_size: usize,
    compressed_data: Bytes,
    digest: Option<Digest>,
}

impl Compressed {
    /// Creates a new `Compressed` object with the given checksum, uncompressed size, compressed data, and digest.
    ///
    /// This is a low-level function that does not check the validity of the compressed data.
    ///
    /// Returns `None` if the compressed data is larger than the uncompressed size.
    pub fn new(checksum: u32, uncompressed_size: usize, compressed_data: Bytes, digest: Option<Digest>) -> anyhow::Result<Self> {
        if compressed_data.len() > uncompressed_size {
            bail!("Compressed data is larger than uncompressed size");
        }
        Ok(Self {
            checksum,
            uncompressed_size,
            compressed_data,
            digest,
        })
    }

    /// Creates a new `Compressed` object from the given uncompressed data and digest.
    ///
    /// The uncompressed data is compressed using the DEFLATE format with a compression level of 6.
    ///
    /// If the compressed data is smaller than the uncompressed data, the compressed data is stored in the `compressed_data` field.
    /// Otherwise, the uncompressed data is stored in the `compressed_data` field.
    pub fn from_uncompressed_data(uncompressed_data: Bytes, digest: Option<Digest>) -> Self
    {
        let compressed_data = Bytes::from(compress_to_vec(uncompressed_data.as_ref(), 6));
        let checksum = crc32(uncompressed_data.as_ref());
        let uncompressed_size = uncompressed_data.as_ref().len();
        let compressed_size = compressed_data.len();
        if compressed_size != 0 && compressed_size < uncompressed_size {
            Self {
                checksum,
                uncompressed_size,
                compressed_data,
                digest,
            }
        } else {
            Self {
                checksum,
                uncompressed_size,
                compressed_data: uncompressed_data,
                digest,
            }
        }
    }

    /// Uncompresses the compressed data and returns the uncompressed data.
    ///
    /// Returns an error if the compressed data is corrupt or the checksum does not match the uncompressed data.
    pub fn uncompress(&self) -> anyhow::Result<Bytes> {
        let compressed_size = self.compressed_data.len();
        if compressed_size >= self.uncompressed_size {
            return Ok(self.compressed_data.clone());
        }

        let uncompressed_data = Bytes::from(decompress_to_vec(&self.compressed_data).map_err(|_| anyhow!("corrupt compressed data"))?);
        if crc32(&uncompressed_data) != self.checksum {
            bail!("compressed data checksum mismatch");
        }

        Ok(uncompressed_data)
    }

    /// Returns the size of the compressed data.
    pub fn compressed_size(&self) -> usize {
        self.compressed_data.len()
    }

    /// Returns the compression ratio of the compressed data.
    pub fn compression_ratio(&self) -> f64 {
        self.compressed_size() as f64 / self.uncompressed_size as f64
    }

    /// Returns a reference to the digest of the compressed data, if it exists.
    pub fn digest_ref_opt(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }

    /// Returns `true` if the compressed data has a digest.
    pub fn has_digest(&self) -> bool {
        self.digest.is_some()
    }
}

impl DigestProvider for Compressed {
    fn digest(&self) -> Cow<'_, Digest> {
        Cow::Owned(self.digest.as_ref().unwrap().clone())
    }
}

impl std::fmt::Debug for Compressed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compressed(checksum: {}, size: {}/{}, ratio: {:.2}, digest: {})",
            hex::encode(self.checksum.to_be_bytes()),
            self.compressed_size(),
            self.uncompressed_size,
            self.compression_ratio(),
            self.digest_ref_opt()
                .map(|d| d.short_description())
                .unwrap_or_else(|| "None".to_string())
        )
    }
}

impl AsRef<Compressed> for Compressed {
    fn as_ref(&self) -> &Compressed {
        self
    }
}

impl CBORTagged for Compressed {
    const CBOR_TAG: Tag = tags::COMPRESSED;
}

impl CBOREncodable for Compressed {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Compressed {
    fn untagged_cbor(&self) -> CBOR {
        let mut elements = vec![
            self.checksum.cbor(),
            self.uncompressed_size.cbor(),
            CBOR::byte_string(&self.compressed_data),
        ];
        if let Some(digest) = &self.digest {
            elements.push(digest.cbor());
        }
        CBOR::Array(elements)
    }
}

impl UREncodable for Compressed { }

impl CBORDecodable for Compressed {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Compressed {
    fn from_untagged_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        let elements = cbor.expect_array()?;
        if elements.len() < 3 || elements.len() > 4 {
            bail!("invalid number of elements in compressed");
        }
        let checksum = u32::from_cbor(&elements[0])?;
        let uncompressed_size = usize::from_cbor(&elements[1])?;
        let compressed_data = elements[2].expect_byte_string()?;
        let digest = if elements.len() == 4 {
            Some(Digest::from_cbor(&elements[3])?)
        } else {
            None
        };
        Self::new(checksum, uncompressed_size, compressed_data, digest)
    }
}

impl URDecodable for Compressed { }

impl URCodable for Compressed { }

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::Compressed;

    #[test]
    fn test_1() {
        let source = Bytes::from("Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium.");
        let compressed = Compressed::from_uncompressed_data(source.clone(), None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 3eeb10a0, size: 217/364, ratio: 0.60, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }

    #[test]
    fn test_2() {
        let source = Bytes::from("Lorem ipsum dolor sit amet consectetur adipiscing");
        let compressed = Compressed::from_uncompressed_data(source.clone(), None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 29db1793, size: 45/49, ratio: 0.92, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }

    #[test]
    fn test_3() {
        let source = Bytes::from("Lorem");
        let compressed = Compressed::from_uncompressed_data(source.clone(), None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 44989b39, size: 5/5, ratio: 1.00, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }

    #[test]
    fn test_4() {
        let source = Bytes::from("");
        let compressed = Compressed::from_uncompressed_data(source.clone(), None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 00000000, size: 0/0, ratio: NaN, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }
}
