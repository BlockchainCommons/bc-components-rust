use crate::EncapsulationPublicKey;

pub trait Encrypter {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;
}
