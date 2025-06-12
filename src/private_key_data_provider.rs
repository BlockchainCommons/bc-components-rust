/// A trait for types that can provide unique data for cryptographic key
/// derivation.
///
/// Types implementing `PrivateKeyDataProvider` can be used as seed material for
/// cryptographic key derivation. The provided data should be sufficiently
/// random and unpredictable to ensure the security of the derived keys.
///
/// This trait is particularly useful for:
/// - Deterministic key generation systems
/// - Key recovery mechanisms
/// - Key derivation hierarchies
/// - Hierarchical deterministic wallet implementations
///
/// # Security Considerations
///
/// Implementers of this trait should ensure that:
/// - The data they provide has sufficient entropy
/// - The data is properly protected in memory
/// - Any serialization or storage is done securely
/// - Appropriate zeroization occurs when data is no longer needed
pub trait PrivateKeyDataProvider {
    /// Returns unique data from which cryptographic keys can be derived.
    ///
    /// The returned data should be sufficiently random and have enough entropy
    /// to serve as the basis for secure cryptographic key derivation.
    ///
    /// # Returns
    ///
    /// A vector of bytes containing the private key data.
    fn private_key_data(&self) -> Vec<u8>;
}

/// Implementation of `PrivateKeyDataProvider` for any type that can be
/// referenced as a byte slice.
///
/// This allows any type that implements `AsRef<[u8]>` to be used as a source of
/// private key data.
impl PrivateKeyDataProvider for dyn AsRef<[u8]> {
    fn private_key_data(&self) -> Vec<u8> { self.as_ref().to_vec() }
}
