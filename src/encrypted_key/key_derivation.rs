use dcbor::prelude::*;

use crate::{EncryptedMessage, Result, SymmetricKey};

/// Trait for key derivation implementations.
pub trait KeyDerivation: CBORCodable {
    const INDEX: usize;

    fn lock(
        &mut self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage>;

    fn unlock(
        &self,
        encrypted_message: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey>;
}
