use dcbor::prelude::*;

use anyhow::Result;

use super::{ EncryptedMessage, SymmetricKey };

/// Trait for key derivation implementations.
pub trait KeyDerivation: Into<CBOR> + TryFrom<CBOR> + Clone {
    const INDEX: usize;

    fn lock(&self, content_key: &SymmetricKey, secret: impl AsRef<[u8]>) -> EncryptedMessage;
    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl AsRef<[u8]>
    ) -> Result<SymmetricKey>;
}
