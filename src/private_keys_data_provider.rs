use bytes::Bytes;

/// Types can implement to `PrivateKeysDataProvider` to indicate that they will provide
/// unique data from which keys for signing and encryption can be derived.
pub trait PrivateKeysDataProvider {
    /// Returns the private key data.
    fn private_keys_data(&self) -> Bytes;
}

impl PrivateKeysDataProvider for dyn AsRef<[u8]> {
    fn private_keys_data(&self) -> Bytes {
        self.as_ref().to_vec().into()
    }
}
