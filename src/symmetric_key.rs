use crate::{EncryptedMessage, Nonce};

pub struct SymmetricKey { }

impl SymmetricKey {
    pub fn encrypt_with_nonce<D1, D2>(&self, plaintext: &D1, aad: Option<&D2>, nonce: &Nonce) -> EncryptedMessage
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
    {
        todo!()
    }

    pub fn encrypt<D1, D2>(&self, plaintext: &D1, aad: Option<&D2>) -> EncryptedMessage
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
    {
        self.encrypt_with_nonce(plaintext, aad, &Nonce::new())
    }
}
