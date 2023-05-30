pub trait ECKeyBaseTrait {
    const KEY_LENGTH: usize;

    fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]>, Self: Sized;
}
