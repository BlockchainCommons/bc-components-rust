use crate::{ECKey, ECUncompressedPublicKey, ECPublicKey};

pub trait ECPublicKeyBase: ECKey {
    fn compressed(&self) -> ECPublicKey;
    fn uncompressed(&self) -> ECUncompressedPublicKey;
}
