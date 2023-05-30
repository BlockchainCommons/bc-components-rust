use crate::{ECKeyTrait, ECUncompressedPublicKey, ECPublicKey};

pub trait ECPublicKeyTrait: ECKeyTrait {
    fn compressed(&self) -> ECPublicKey;
    fn uncompressed(&self) -> ECUncompressedPublicKey;
}
