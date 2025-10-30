use bc_crypto::ECDSA_SIGNATURE_SIZE;
use bc_ur::prelude::*;

use crate::{
    Digest, ECKey, ECKeyBase, ECPublicKeyBase, Error, Reference,
    ReferenceProvider, Result, Signature, Verifier, tags,
};

/// The size of an ECDSA compressed public key in bytes (33 bytes).
pub const ECDSA_PUBLIC_KEY_SIZE: usize = bc_crypto::ECDSA_PUBLIC_KEY_SIZE;

/// A compressed elliptic curve digital signature algorithm (ECDSA) public key.
///
/// An `ECPublicKey` is a 33-byte compressed representation of a public key on
/// the secp256k1 curve. The first byte is a prefix (0x02 or 0x03) that
/// indicates the parity of the y-coordinate, followed by the 32-byte
/// x-coordinate.
///
/// These public keys are used to:
/// - Verify ECDSA signatures
/// - Identify the owner of a private key without revealing the private key
/// - Derive shared secrets (when combined with another party's private key)
///
/// Unlike the larger 65-byte uncompressed format (`ECUncompressedPublicKey`),
/// compressed public keys save space while providing the same cryptographic
/// security.
///
/// # Examples
///
/// Verifying an ECDSA signature:
///
/// ```
/// use bc_components::{ECKey, ECPrivateKey, ECPublicKey};
///
/// // Generate a keypair
/// let private_key = ECPrivateKey::new();
/// let public_key = private_key.public_key();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.ecdsa_sign(message);
///
/// // Verify the signature
/// assert!(public_key.verify(&signature, message));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPublicKey([u8; ECDSA_PUBLIC_KEY_SIZE]);

impl ECPublicKey {
    /// Restores an ECDSA public key from an array of bytes.
    ///
    /// This method performs no validation on the input data.
    pub const fn from_data(data: [u8; ECDSA_PUBLIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Returns the ECDSA public key as an array of bytes.
    pub fn data(&self) -> &[u8; ECDSA_PUBLIC_KEY_SIZE] { &self.0 }

    /// Get the ECDSA public key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }
}

impl ECPublicKey {
    /// Verifies an ECDSA signature for a message using this public key.
    ///
    /// Returns `true` if the signature is valid for the given message and this
    /// public key, and `false` otherwise.
    ///
    /// # Parameters
    /// - `signature`: A 70-72 byte DER-encoded ECDSA signature
    /// - `message`: The message that was signed
    pub fn verify(
        &self,
        signature: &[u8; ECDSA_SIGNATURE_SIZE],
        message: impl AsRef<[u8]>,
    ) -> bool {
        bc_crypto::ecdsa_verify(&self.0, signature, message)
    }
}

impl AsRef<[u8]> for ECPublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Formats the key for debugging, showing type name and hexadecimal value.
impl std::fmt::Debug for ECPublicKey {
    /// Displays the key with type information and hexadecimal value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPublicKey({})", self.hex())
    }
}

/// Implements the `ECKeyBase` trait methods for `ECPublicKey`.
impl ECKeyBase for ECPublicKey {
    /// The size of an EC compressed public key (33 bytes).
    const KEY_SIZE: usize = bc_crypto::ECDSA_PUBLIC_KEY_SIZE;

    /// Creates a key from a byte slice, with validation.
    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let data = data.as_ref();
        if data.len() != ECDSA_PUBLIC_KEY_SIZE {
            return Err(Error::invalid_size(
                "ECDSA public key",
                ECDSA_PUBLIC_KEY_SIZE,
                data.len(),
            ));
        }
        let mut key = [0u8; ECDSA_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    /// Returns the key as a byte slice.
    fn data(&self) -> &[u8] { self.into() }
}

/// Implements the `Verifier` trait for verifying signatures.
impl Verifier for ECPublicKey {
    /// Verifies a signature for a message using this public key.
    ///
    /// Only supports ECDSA signatures; returns `false` for other signature
    /// types.
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        match signature {
            Signature::ECDSA(sig) => self.verify(sig, message),
            _ => false,
        }
    }
}

/// Implements the `ECKey` trait for `ECPublicKey`.
impl ECKey for ECPublicKey {
    /// Returns the public key (self).
    fn public_key(&self) -> ECPublicKey { self.clone() }
}

/// Implements the `ECPublicKeyBase` trait for converting to uncompressed
/// format.
impl ECPublicKeyBase for ECPublicKey {
    /// Converts this compressed public key to its uncompressed form.
    fn uncompressed_public_key(&self) -> crate::ECUncompressedPublicKey {
        bc_crypto::ecdsa_decompress_public_key(&self.0).into()
    }
}

/// Converts a reference to an `ECPublicKey` to a reference to a fixed-size byte
/// array.
impl<'a> From<&'a ECPublicKey> for &'a [u8; ECPublicKey::KEY_SIZE] {
    /// Returns a reference to the underlying byte array.
    fn from(value: &'a ECPublicKey) -> Self { &value.0 }
}

/// Converts a fixed-size byte array to an `ECPublicKey`.
impl From<[u8; ECDSA_PUBLIC_KEY_SIZE]> for ECPublicKey {
    /// Converts a 33-byte array into an EC public key.
    fn from(value: [u8; ECDSA_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

/// Converts a reference to an `ECPublicKey` to a reference to a byte slice.
impl<'a> From<&'a ECPublicKey> for &'a [u8] {
    /// Returns a reference to the key as a byte slice.
    fn from(value: &'a ECPublicKey) -> Self { &value.0 }
}

/// Defines CBOR tags for EC keys.
impl CBORTagged for ECPublicKey {
    /// Returns the CBOR tags for EC keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_EC_KEY, tags::TAG_EC_KEY_V1])
    }
}

/// Converts an `ECPublicKey` to CBOR.
impl From<ECPublicKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: ECPublicKey) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for EC public keys.
impl CBORTaggedEncodable for ECPublicKey {
    /// Creates the untagged CBOR representation.
    ///
    /// The format is a map with:
    /// - Key 3: byte string of the key data (Note the absence of key 2, which
    ///   would indicate a private key)
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(3, CBOR::to_byte_string(self.0));
        m.into()
    }
}

impl ReferenceProvider for ECPublicKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl std::fmt::Display for ECPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPublicKey({})", self.ref_hex_short())
    }
}
