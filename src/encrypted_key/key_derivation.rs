use anyhow::Result;
use dcbor::prelude::*;

use crate::{EncryptedMessage, SymmetricKey};

/// Trait for key derivation implementations.
pub trait KeyDerivation: CBORCodable {
    const INDEX: usize;

    fn lock(
        &self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage>;

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey>;
}
