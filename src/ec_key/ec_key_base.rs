use crate::ECPublicKey;

pub trait ECKeyBase:
    std::fmt::Display +
    std::fmt::Debug +
    Clone +
    PartialEq + Eq +
    core::hash::Hash
{
    const KEY_SIZE: usize;

    fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]>, Self: Sized;
    fn data(&self) -> &[u8];

    fn hex(&self) -> String {
        hex::encode(self.data())
    }

    fn from_hex(hex: &str) -> Option<Self> {
        let data = hex::decode(hex).ok()?;
        Self::from_data_ref(&data)
    }
}

pub trait ECKey: ECKeyBase {
    fn public_key(&self) -> ECPublicKey;
}
