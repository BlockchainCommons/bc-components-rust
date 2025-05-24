use std::{env, path::Path};

use anyhow::{Context, Result, bail};
use bc_crypto::hkdf_hmac_sha256;
use dcbor::prelude::*;
use ssh_agent_client_rs::Client;

use super::{KeyDerivation, KeyDerivationMethod, SALT_LEN};
use crate::{EncryptedMessage, Nonce, Salt, SymmetricKey};

/// Struct representing SSH Agent parameters.
///
/// CDDL:
/// ```cddl
/// SSHAgentParams = [4, Salt, id: tstr]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHAgentParams {
    salt: Salt,
    id: String,
}

impl SSHAgentParams {
    pub fn new() -> Self {
        Self::new_opt(Salt::new_with_len(SALT_LEN).unwrap(), String::new())
    }

    pub fn new_opt(salt: Salt, id: String) -> Self { Self { salt, id } }

    pub fn salt(&self) -> &Salt { &self.salt }

    pub fn id(&self) -> &String { &self.id }
}

/// Connect to whatever socket/pipe `$SSH_AUTH_SOCK` points at.
fn connect_to_agent() -> Result<Client> {
    let sock =
        env::var("SSH_AUTH_SOCK").context("SSH_AUTH_SOCK env var not set")?;
    Client::connect(Path::new(&sock)).context("no ssh-agent reachable")
}

impl KeyDerivation for SSHAgentParams {
    const INDEX: usize = KeyDerivationMethod::SSHAgent as usize;

    fn lock(
        &self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        // Convert `secret` to a string for the SSH ID.
        let id = String::from_utf8(secret.as_ref().to_vec())
            .context("SSH Agent secret must be a valid UTF-8 string")?;

        // Connect to the SSH agent.
        let mut agent = connect_to_agent()?;

        // List all identities in the SSH agent.
        let ids = agent.list_identities()?;

        // Filter down to the identities that have Ed25519 keys.
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|k| k.key_data().ed25519().is_some())
            .collect();

        if ids.is_empty() {
            bail!("No Ed25519 identities available in SSH agent");
        }

        // If `id` is empty, use the first available identity, otherwise find
        // the one matching `id`.
        let identity = if id.is_empty() {
            // Safe to unwrap because we checked that `ids` is not empty
            ids.first().unwrap()
        } else {
            ids.iter()
                .find(|k| k.comment() == id)
                .context("No matching identity found")?
        };

        // Safe to unwrap because SALT_LEN is a valid length for Salt.
        let salt = Salt::new_with_len(SALT_LEN).unwrap();

        // Sign the salt with the identity.
        let sig = agent
            .sign(identity, salt.data())
            .context("SSH agent refused to sign")?;

        // Derive the symmetric key using HKDF with HMAC-SHA256.
        let derived_key = SymmetricKey::from_data_ref(hkdf_hmac_sha256(
            &sig,
            &salt,
            SymmetricKey::SYMMETRIC_KEY_SIZE,
        ))
        .unwrap(); // Safe to unwrap because SYMMETRIC_KEY_SIZE is valid.

        // Encode the method as CBOR data.
        let encoded_method = Self::new_opt(salt, id).to_cbor_data();

        // Encrypt the content key with the derived key, using the
        // encoded method as additional authenticated data.
        Ok(derived_key.encrypt(
            content_key,
            Some(encoded_method),
            Option::<Nonce>::None,
        ))
    }

    fn unlock(
        &self,
        encrypted_key: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey> {
        // Convert `secret` to a string for the SSH ID.
        let id = String::from_utf8(secret.as_ref().to_vec())
            .context("SSH Agent secret must be a valid UTF-8 string")?;

        // Connect to the SSH agent.
        let mut agent = connect_to_agent()?;

        // List all identities in the SSH agent.
        let ids = agent.list_identities()?;

        // Filter down to the identities that have Ed25519 keys.
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|k| k.key_data().ed25519().is_some())
            .collect();

        if ids.is_empty() {
            bail!("No Ed25519 identities available in SSH agent");
        }

        // id priority:
        // 1. `id` passed in as secret if not empty,
        // 2. `self.id` if not empty,
        // 3. first available identity.
        let identity = if !id.is_empty() {
            ids.iter()
                .find(|k| k.comment() == id)
                .context("No matching identity found")?
        } else if !self.id.is_empty() {
            ids.iter()
                .find(|k| k.comment() == self.id)
                .context("No matching identity found")?
        } else {
            // Safe to unwrap because we checked that `ids` is not empty
            ids.first().unwrap()
        };

        // Sign the salt with the identity.
        let sig = agent
            .sign(identity, self.salt.data())
            .context("SSH agent refused to sign")?;

        // Derive the symmetric key using HKDF with HMAC-SHA256.
        let derived_key = SymmetricKey::from_data_ref(hkdf_hmac_sha256(
            &sig,
            &self.salt,
            SymmetricKey::SYMMETRIC_KEY_SIZE,
        ))
        .unwrap(); // Safe to unwrap because SYMMETRIC_KEY_SIZE is valid.

        // Decrypt the encrypted key with the derived key.
        let decrypted_key = derived_key
            .decrypt(encrypted_key)
            .context("Failed to decrypt the encrypted key")?;

        let content_key = decrypted_key
            .try_into()
            .context("Failed to convert decrypted key to SymmetricKey")?;

        // If the decryption was successful, return the symmetric key.
        Ok(content_key)
    }
}

impl std::fmt::Display for SSHAgentParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHAgent({})", self.id)
    }
}

impl Into<CBOR> for SSHAgentParams {
    fn into(self) -> CBOR {
        vec![CBOR::from(Self::INDEX), self.salt.into(), self.id.into()].into()
    }
}

impl TryFrom<CBOR> for SSHAgentParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let a = cbor.try_into_array()?;
        a.len()
            .eq(&3)
            .then_some(())
            .ok_or_else(|| dcbor::Error::msg("Invalid SSHAgentParams"))?;
        let mut iter = a.into_iter();
        let _index: usize = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing index"))?
            .try_into()?;
        let salt: Salt = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing salt"))?
            .try_into()?;
        let id: String = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("Missing id"))?
            .try_into()?;
        Ok(SSHAgentParams { salt, id })
    }
}
