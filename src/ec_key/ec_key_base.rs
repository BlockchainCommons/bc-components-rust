use bc_ur::UREncodable;

use crate::{ECPublicKey, Result};

/// A base trait for all elliptic curve keys.
///
/// This trait defines common functionality for all elliptic curve keys,
/// including both private and public keys. It provides methods for key
/// construction from binary data and hexadecimal strings, as well as conversion
/// to hexadecimal format.
///
/// All EC key types have a fixed size depending on their specific type:
/// - EC private keys: 32 bytes
/// - EC compressed public keys: 33 bytes
/// - EC uncompressed public keys: 65 bytes
/// - Schnorr public keys: 32 bytes
pub trait ECKeyBase:
    std::fmt::Display + std::fmt::Debug + Clone + PartialEq + Eq + core::hash::Hash
{
    /// The size of the key in bytes.
    const KEY_SIZE: usize;

    /// Creates a key from a reference to binary data.
    ///
    /// Returns an error if the data is not valid for this key type.
    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized;

    /// Returns the key's binary data.
    fn data(&self) -> &[u8];

    /// Returns the key as a hexadecimal string.
    fn hex(&self) -> String { hex::encode(self.data()) }

    /// Creates a key from a hexadecimal string.
    ///
    /// Returns an error if the string is not valid hexadecimal or if the
    /// resulting data is not valid for this key type.
    fn from_hex(hex: impl AsRef<str>) -> Result<Self> {
        let data = hex::decode(hex.as_ref())?;
        Self::from_data_ref(data)
    }
}

/// A trait for elliptic curve keys that can derive a public key.
///
/// This trait extends `ECKeyBase` to provide a method for deriving
/// the corresponding compressed public key. It is implemented by both
/// private keys (where it generates the public key) and public keys
/// (where it may return self or convert between formats).
pub trait ECKey: ECKeyBase + UREncodable {
    /// Returns the compressed public key corresponding to this key.
    fn public_key(&self) -> ECPublicKey;
}
