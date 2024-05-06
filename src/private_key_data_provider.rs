use bytes::Bytes;

/// Types can implement to `PrivateKeyDataProvider` to indicate that they will provide
/// unique data from which keys for signing and encryption can be derived.
pub trait PrivateKeyDataProvider {
    /// Returns the private key data.
    fn private_key_data(&self) -> Bytes;
}

impl PrivateKeyDataProvider for dyn AsRef<[u8]> {
    fn private_key_data(&self) -> Bytes {
        self.as_ref().to_vec().into()
    }
}
