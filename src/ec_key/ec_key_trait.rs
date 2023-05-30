use crate::{ECKeyBaseTrait, ECPublicKey};

pub trait ECKeyTrait: ECKeyBaseTrait {
    fn public_key(&self) -> ECPublicKey;
}
