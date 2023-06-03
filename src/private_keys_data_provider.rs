/// Types can implement to `PrivateKeysDataProvider` to indicate that they will provide
/// unique data from which keys for signing and encryption can be derived.
pub trait PrivateKeysDataProvider {
    fn private_keys_data(&self) -> Vec<u8>;
}

impl PrivateKeysDataProvider for dyn AsRef<[u8]> {
    fn private_keys_data(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}
