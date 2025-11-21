use bc_ur::prelude::*;

use crate::{
    Digest, ECKey, ECKeyBase, ECPublicKey, ECPublicKeyBase, Error, Reference,
    ReferenceProvider, Result, tags,
};

/// The size of an ECDSA uncompressed public key in bytes (65 bytes).
pub const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE: usize =
    bc_crypto::ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE;

/// An uncompressed elliptic curve digital signature algorithm (ECDSA) public
/// key.
///
/// An `ECUncompressedPublicKey` is a 65-byte representation of a public key on
/// the secp256k1 curve. It consists of:
///
/// - 1 byte prefix (0x04)
/// - 32 bytes for the x-coordinate
/// - 32 bytes for the y-coordinate
///
/// This format explicitly includes both coordinates of the elliptic curve
/// point, unlike the compressed format which only includes the x-coordinate and
/// a single byte to indicate the parity of the y-coordinate.
///
/// This is considered a legacy key type and is not recommended for general use.
/// The compressed format (`ECPublicKey`) is more space-efficient and provides
/// the same cryptographic security. However, some legacy systems or protocols
/// might require the uncompressed format.
///
/// # Examples
///
/// Converting between compressed and uncompressed formats:
///
/// ```
/// use bc_components::{
///     ECKey, ECPrivateKey, ECPublicKey, ECPublicKeyBase,
///     ECUncompressedPublicKey,
/// };
///
/// // Generate a keypair
/// let private_key = ECPrivateKey::new();
/// let compressed_key = private_key.public_key();
///
/// // Convert to uncompressed format
/// let uncompressed_key = compressed_key.uncompressed_public_key();
///
/// // Convert back to compressed format
/// let compressed_again = uncompressed_key.public_key();
///
/// // They should be equal
/// assert_eq!(compressed_key, compressed_again);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ECUncompressedPublicKey([u8; ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE]);

impl ECUncompressedPublicKey {
    /// Restores an ECDSA uncompressed public key from an array of bytes.
    ///
    /// This method performs no validation on the input data.
    pub const fn from_data(
        data: [u8; ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE],
    ) -> Self {
        Self(data)
    }
}

/// Formats the key for debugging, showing type name and hexadecimal value.
impl std::fmt::Debug for ECUncompressedPublicKey {
    /// Displays the key with type information and hexadecimal value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECUncompressedPublicKey({})", self.hex())
    }
}

/// Implements the `ECKeyBase` trait methods for `ECUncompressedPublicKey`.
impl ECKeyBase for ECUncompressedPublicKey {
    /// The size of an EC uncompressed public key (65 bytes).
    const KEY_SIZE: usize = bc_crypto::ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE;

    /// Creates a key from a byte slice, with validation.
    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let data = data.as_ref();
        if data.len() != ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE {
            return Err(Error::invalid_size(
                "ECDSA uncompressed public key",
                ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE,
                data.len(),
            ));
        }
        let mut key = [0u8; ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    /// Returns the key as a byte slice.
    fn data(&self) -> &[u8] { &self.0 }
}

/// Implements the `ECKey` trait for converting to compressed format.
impl ECKey for ECUncompressedPublicKey {
    /// Converts this uncompressed public key to its compressed form.
    fn public_key(&self) -> ECPublicKey {
        bc_crypto::ecdsa_compress_public_key(&self.0).into()
    }
}

/// Implements the `ECPublicKeyBase` trait.
impl ECPublicKeyBase for ECUncompressedPublicKey {
    /// Returns this uncompressed public key (self).
    fn uncompressed_public_key(&self) -> ECUncompressedPublicKey {
        *self
    }
}

/// Converts a fixed-size byte array to an `ECUncompressedPublicKey`.
impl From<[u8; ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE]>
    for ECUncompressedPublicKey
{
    /// Converts a 65-byte array into an EC uncompressed public key.
    fn from(value: [u8; ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

/// Provides a reference to the key data as a byte slice.
impl AsRef<[u8]> for ECUncompressedPublicKey {
    /// Returns a reference to the key as a byte slice.
    fn as_ref(&self) -> &[u8] { self.data() }
}

/// Defines CBOR tags for EC keys.
impl CBORTagged for ECUncompressedPublicKey {
    /// Returns the CBOR tags for EC keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_EC_KEY, tags::TAG_EC_KEY_V1])
    }
}

/// Converts an `ECUncompressedPublicKey` to CBOR.
impl From<ECUncompressedPublicKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: ECUncompressedPublicKey) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for EC uncompressed public keys.
impl CBORTaggedEncodable for ECUncompressedPublicKey {
    /// Creates the untagged CBOR representation.
    ///
    /// The format is a map with:
    /// - Key 3: byte string of the key data
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(3, CBOR::to_byte_string(self.0));
        m.into()
    }
}

impl ReferenceProvider for ECUncompressedPublicKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl std::fmt::Display for ECUncompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECUncompressedPublicKey({})", self.ref_hex_short())
    }
}
