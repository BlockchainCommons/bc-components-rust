use crate::{ECKey, ECUncompressedPublicKey};

pub trait ECPublicKeyBase: ECKey {
    fn uncompressed_public_key(&self) -> ECUncompressedPublicKey;
}
