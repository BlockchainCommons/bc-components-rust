use anyhow::{bail, Result};
use bc_crypto::SCHNORR_SIGNATURE_SIZE;

use crate::ECKeyBase;

/// The size of a Schnorr public key in bytes (32 bytes).
pub const SCHNORR_PUBLIC_KEY_SIZE: usize = bc_crypto::SCHNORR_PUBLIC_KEY_SIZE;

/// A Schnorr (x-only) elliptic curve public key.
///
/// A `SchnorrPublicKey` is a 32-byte "x-only" public key used with the BIP-340
/// Schnorr signature scheme. Unlike compressed ECDSA public keys (33 bytes) that
/// include a prefix byte indicating the parity of the y-coordinate, Schnorr public
/// keys only contain the x-coordinate of the elliptic curve point.
///
/// Schnorr signatures offer several advantages over traditional ECDSA signatures:
///
/// - **Linearity**: Enables key and signature aggregation (eg., for multisignature schemes)
/// - **Non-malleability**: Prevents third parties from modifying signatures
/// - **Smaller size**: Signatures are 64 bytes vs 70-72 bytes for ECDSA
/// - **Better privacy**: Makes different multisig policies indistinguishable
/// - **Provable security**: Requires fewer cryptographic assumptions than ECDSA
///
/// Schnorr signatures were introduced to Bitcoin via the Taproot upgrade (BIP-340)
/// and are becoming more widely used in cryptocurrency applications.
///
/// # Examples
///
/// Verifying a Schnorr signature:
///
/// ```
/// use bc_components::ECPrivateKey;
///
/// // Generate a private key
/// let private_key = ECPrivateKey::new();
///
/// // Get the Schnorr public key
/// let schnorr_public_key = private_key.schnorr_public_key();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.schnorr_sign(message);
///
/// // Verify the signature
/// assert!(schnorr_public_key.schnorr_verify(&signature, message));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SchnorrPublicKey([u8; SCHNORR_PUBLIC_KEY_SIZE]);

impl SchnorrPublicKey {
    /// Restores a Schnorr public key from an array of bytes.
    ///
    /// This method performs no validation on the input data.
    pub const fn from_data(data: [u8; SCHNORR_PUBLIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Returns the Schnorr public key as an array of bytes.
    pub fn data(&self) -> &[u8; SCHNORR_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl SchnorrPublicKey {
    /// Verifies a Schnorr signature for a message using this public key.
    ///
    /// Returns `true` if the signature is valid for the given message and this public key,
    /// and `false` otherwise.
    ///
    /// This implementation follows the BIP-340 Schnorr signature verification algorithm.
    ///
    /// # Parameters
    /// - `signature`: A 64-byte Schnorr signature
    /// - `message`: The message that was signed
    pub fn schnorr_verify(&self, signature: &[u8; SCHNORR_SIGNATURE_SIZE], message: impl AsRef<[u8]>) -> bool {
        bc_crypto::schnorr_verify(self.into(), signature, message)
    }
}

/// Converts a reference to a `SchnorrPublicKey` to a reference to a fixed-size byte array.
impl<'a> From<&'a SchnorrPublicKey> for &'a [u8; SchnorrPublicKey::KEY_SIZE] {
    /// Returns a reference to the underlying byte array.
    fn from(value: &'a SchnorrPublicKey) -> Self {
        &value.0
    }
}

/// Converts a fixed-size byte array to a `SchnorrPublicKey`.
impl From<[u8; SCHNORR_PUBLIC_KEY_SIZE]> for SchnorrPublicKey {
    /// Converts a 32-byte array into a Schnorr public key.
    fn from(value: [u8; SCHNORR_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

/// Provides a reference to the key data as a byte slice.
impl AsRef<[u8]> for SchnorrPublicKey {
    /// Returns a reference to the key as a byte slice.
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

/// Formats the key as a hexadecimal string.
impl std::fmt::Display for SchnorrPublicKey {
    /// Displays the key as a hexadecimal string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

/// Formats the key for debugging, showing type name and hexadecimal value.
impl std::fmt::Debug for SchnorrPublicKey {
    /// Displays the key with type information and hexadecimal value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SchnorrPublicKey({})", self.hex())
    }
}

/// Implements the `ECKeyBase` trait methods for `SchnorrPublicKey`.
impl ECKeyBase for SchnorrPublicKey {
    /// The size of a Schnorr public key (32 bytes).
    const KEY_SIZE: usize = bc_crypto::SCHNORR_PUBLIC_KEY_SIZE;

    /// Creates a key from a byte slice, with validation.
    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != SCHNORR_PUBLIC_KEY_SIZE {
            bail!("invalid Schnorr public key size");
        }
        let mut key = [0u8; SCHNORR_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    /// Returns the key as a byte slice.
    fn data(&self) -> &[u8] {
        &self.0
    }
}
