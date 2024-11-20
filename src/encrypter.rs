use crate::AgreementPublicKey;

pub trait Encrypter {
    fn agreement_public_key(&self) -> &AgreementPublicKey;
}
