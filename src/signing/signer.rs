use anyhow::Result;

use crate::{Signature, SigningOptions};

pub trait Signer {
    fn sign_with_options(
        &self,
        message: &dyn AsRef<[u8]>,
        options: Option<SigningOptions>
    ) -> Result<Signature>;

    fn sign(&self, message: &dyn AsRef<[u8]>) -> Result<Signature> {
        self.sign_with_options(message, None)
    }
}

pub trait Verifier {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool;
}
