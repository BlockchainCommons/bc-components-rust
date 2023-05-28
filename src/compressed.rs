use std::{fmt::Formatter, rc::Rc, borrow::Cow};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable};
use bc_crypto::hash::crc32;
use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::decompress_to_vec;
use crate::{digest::Digest, DigestProvider, tags_registry};

/// Errors for Compressed
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub enum Error {
    /// The compressed data is corrupt.
    Corrupt,
    /// The checksum does not match the uncompressed data.
    InvalidChecksum,
}

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
    compressed_data: Vec<u8>,
    digest: Option<Digest>,
}

impl Compressed {
    pub fn new(checksum: u32, uncompressed_size: usize, compressed_data: Vec<u8>, digest: Option<Digest>) -> Option<Self> {
        if compressed_data.len() > uncompressed_size {
            return None;
        }
        Some(Self {
            checksum,
            uncompressed_size,
            compressed_data,
            digest,
        })
    }

    pub fn from_uncompressed_data(uncompressed_data: &[u8], digest: Option<Digest>) -> Self {
        let compressed_data = compress_to_vec(uncompressed_data, 6);
        let checksum = crc32(uncompressed_data);
        let uncompressed_size = uncompressed_data.len();
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
                compressed_data: uncompressed_data.to_vec(),
                digest,
            }
        }
    }

    pub fn uncompress(&self) -> Result<Vec<u8>, Error> {
        let compressed_size = self.compressed_data.len();
        if compressed_size >= self.uncompressed_size {
            return Ok(self.compressed_data.clone());
        }

        let uncompressed_data = decompress_to_vec(&self.compressed_data).map_err(|_| Error::Corrupt)?;
        if crc32(&uncompressed_data) != self.checksum {
            return Err(Error::InvalidChecksum);
        }

        Ok(uncompressed_data)
    }

    pub fn compressed_size(&self) -> usize {
        self.compressed_data.len()
    }

    pub fn compression_ratio(&self) -> f64 {
        self.compressed_size() as f64 / self.uncompressed_size as f64
    }

    pub fn digest_ref_opt(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }

    pub fn has_digest(&self) -> bool {
        self.digest.is_some()
    }
}

impl DigestProvider for Compressed {
    fn digest(&self) -> Cow<Digest> {
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

impl CBORTagged for Compressed {
    const CBOR_TAG: Tag = tags_registry::COMPRESSED;
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
            self.compressed_data.cbor(),
        ];
        if let Some(digest) = &self.digest {
            elements.push(digest.cbor());
        }
        CBOR::Array(elements)
    }
}

impl UREncodable for Compressed { }

impl CBORDecodable for Compressed {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Compressed {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let elements = cbor.as_array()?;
        if elements.len() < 3 || elements.len() > 4 {
            return Err(dcbor::Error::InvalidFormat);
        }
        let checksum = *u32::from_cbor(&elements[0])?;
        let uncompressed_size = *usize::from_cbor(&elements[1])?;
        let compressed_data = Vec::<u8>::from_cbor(&elements[2])?.as_ref().clone();
        let digest = if elements.len() == 4 {
            Some(Digest::from_cbor(&elements[3])?.as_ref().clone())
        } else {
            None
        };
        Ok(
            Rc::new(
                Self::new(checksum, uncompressed_size, compressed_data, digest)
                    .ok_or(dcbor::Error::InvalidFormat)?
            )
        )
    }
}

impl URDecodable for Compressed { }

impl URCodable for Compressed { }

#[cfg(test)]
mod tests {
    use crate::Compressed;

    #[test]
    fn test_1() {
        let source = "Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium.".as_bytes();
        let compressed = Compressed::from_uncompressed_data(source, None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 3eeb10a0, size: 217/364, ratio: 0.60, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }

    #[test]
    fn test_2() {
        let source = "Lorem ipsum dolor sit amet consectetur adipiscing".as_bytes();
        let compressed = Compressed::from_uncompressed_data(source, None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 29db1793, size: 45/49, ratio: 0.92, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }

    #[test]
    fn test_3() {
        let source = "Lorem".as_bytes();
        let compressed = Compressed::from_uncompressed_data(source, None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 44989b39, size: 5/5, ratio: 1.00, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }

    #[test]
    fn test_4() {
        let source = "".as_bytes();
        let compressed = Compressed::from_uncompressed_data(source, None);
        assert_eq!(format!("{:?}", compressed), "Compressed(checksum: 00000000, size: 0/0, ratio: NaN, digest: None)");
        assert_eq!(compressed.uncompress().unwrap(), source);
    }
}
