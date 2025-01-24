use anyhow::Result;
use crate::{EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, SymmetricKey};

pub trait Encrypter {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;

    fn encapsulate_new_shared_secret(&self) -> (SymmetricKey, EncapsulationCiphertext) {
        self.encapsulation_public_key().encapsulate_new_shared_secret()
    }
}

pub trait Decrypter {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;

    fn decapsulate_shared_secret(&self, ciphertext: &EncapsulationCiphertext) -> Result<SymmetricKey> {
        self.encapsulation_private_key().decapsulate_shared_secret(ciphertext)
    }
}
