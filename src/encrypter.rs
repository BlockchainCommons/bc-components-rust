use crate::{EncapsulationCiphertext, EncapsulationPublicKey, SymmetricKey};

pub trait Encrypter {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;

    fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, EncapsulationCiphertext) {
        self.encapsulation_public_key().encapsulate_new_shared_secret()
    }
}
