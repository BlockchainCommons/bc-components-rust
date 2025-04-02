use crate::{ECKey, ECUncompressedPublicKey};

/// A trait for elliptic curve public keys that can provide their uncompressed form.
///
/// This trait extends `ECKey` to provide a method for obtaining the uncompressed
/// representation of a public key. Elliptic curve public keys can be represented in
/// both compressed (33 bytes) and uncompressed (65 bytes) formats:
///
/// - Compressed format: Uses a single byte prefix (0x02 or 0x03) followed by the
///   x-coordinate (32 bytes), with the prefix indicating the parity of the y-coordinate.
///
/// - Uncompressed format: Uses a byte prefix (0x04) followed by both x and y coordinates
///   (32 bytes each), for a total of 65 bytes.
///
/// The compressed format is more space-efficient and is recommended for most applications,
/// but some legacy systems require the uncompressed format.
pub trait ECPublicKeyBase: ECKey {
    /// Returns the uncompressed public key representation.
    fn uncompressed_public_key(&self) -> ECUncompressedPublicKey;
}
