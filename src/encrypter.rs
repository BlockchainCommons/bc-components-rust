use crate::X25519PublicKey;

pub trait Encrypter {
    fn agreement_public_key(&self) -> &X25519PublicKey;
}
