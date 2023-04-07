
/// A data provider
pub trait DataProvider {
    /// The provided data
    fn provided_data(&self) -> Vec<u8>;
}

impl DataProvider for Vec<u8> {
    fn provided_data(&self) -> Vec<u8> {
        self.clone()
    }
}

impl DataProvider for String {
    fn provided_data(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
