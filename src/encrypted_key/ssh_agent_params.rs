use std::{cell::RefCell, rc::Rc};
#[cfg(feature = "ssh-agent")]
use std::{env, path::Path};

#[cfg(feature = "ssh-agent")]
use bc_crypto::hkdf_hmac_sha256;
use dcbor::prelude::*;
#[cfg(feature = "ssh-agent")]
use ssh_agent_client_rs::{Client, Identity};

use super::{KeyDerivation, KeyDerivationMethod, SALT_LEN};
#[cfg(feature = "ssh-agent")]
use crate::Nonce;
use crate::{EncryptedMessage, Error, Result, Salt, SymmetricKey};

#[cfg(feature = "ssh-agent")]
#[allow(dead_code)]
pub trait SSHAgent {
    fn list_identities(&mut self) -> Result<Vec<ssh_key::PublicKey>>;
    fn add_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()>;
    fn remove_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()>;
    fn remove_all_identities(&mut self) -> Result<()>;
    fn sign(
        &mut self,
        key: &ssh_key::PublicKey,
        data: &[u8],
    ) -> Result<ssh_key::Signature>;
}

#[cfg(feature = "ssh-agent")]
impl SSHAgent for Client {
    fn list_identities(&mut self) -> Result<Vec<ssh_key::PublicKey>> {
        self.list_all_identities()
            .map(|identities| {
                identities
                    .into_iter()
                    .filter_map(|i| match i {
                        Identity::PublicKey(pk) => Some(pk.into_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .map_err(|e| Error::ssh_agent(e.to_string()))
    }

    fn add_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()> {
        self.add_identity(key)
            .map_err(|e| Error::ssh_agent(e.to_string()))
    }

    fn remove_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()> {
        self.remove_identity(key)
            .map_err(|e| Error::ssh_agent(e.to_string()))
    }

    fn remove_all_identities(&mut self) -> Result<()> {
        self.remove_all_identities()
            .map_err(|e| Error::ssh_agent(e.to_string()))
    }

    fn sign(
        &mut self,
        key: &ssh_key::PublicKey,
        data: &[u8],
    ) -> Result<ssh_key::Signature> {
        self.sign(key, data)
            .map_err(|e| Error::ssh_agent(e.to_string()))
    }
}

// Agent storage
#[cfg(feature = "ssh-agent")]
type AgentBox = Rc<RefCell<dyn SSHAgent>>;

#[cfg(not(feature = "ssh-agent"))]
type AgentBox = Rc<RefCell<dyn std::any::Any>>;

/// Struct representing SSH Agent parameters.
///
/// CDDL:
/// ```cddl
/// SSHAgentParams = [4, Salt, id: tstr]
/// ```
#[derive(Clone)]
pub struct SSHAgentParams {
    salt: Salt,
    id: String,
    #[allow(dead_code)]
    agent: Option<AgentBox>,
}

impl PartialEq for SSHAgentParams {
    fn eq(&self, other: &Self) -> bool {
        self.salt == other.salt && self.id == other.id
    }
}

impl Eq for SSHAgentParams {}

impl std::fmt::Debug for SSHAgentParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SSHAgentParams")
            .field("salt", &self.salt)
            .field("id", &self.id)
            .finish()
    }
}

impl SSHAgentParams {
    pub fn new() -> Self {
        Self::new_opt(
            Salt::new_with_len(SALT_LEN).unwrap(),
            String::new(),
            None,
        )
    }

    pub fn new_opt(
        salt: Salt,
        id: impl AsRef<str>,
        agent: Option<AgentBox>,
    ) -> Self {
        Self { salt, id: id.as_ref().to_string(), agent }
    }

    pub fn salt(&self) -> &Salt { &self.salt }

    pub fn id(&self) -> &String { &self.id }

    pub fn agent(&self) -> Option<AgentBox> { self.agent.clone() }

    pub fn set_agent(&mut self, agent: Option<AgentBox>) { self.agent = agent; }
}

impl Default for SSHAgentParams {
    fn default() -> Self { Self::new() }
}

/// Connect to whatever socket/pipe `$SSH_AUTH_SOCK` points at.
#[cfg(feature = "ssh-agent")]
pub fn connect_to_ssh_agent() -> Result<AgentBox> {
    let sock = env::var("SSH_AUTH_SOCK")
        .map_err(|_| Error::ssh_agent("SSH_AUTH_SOCK env var not set"))?;
    let client = Client::connect(Path::new(&sock))
        .map_err(|_| Error::ssh_agent("no ssh-agent reachable"))?;
    Ok(Rc::new(RefCell::new(client)))
}

#[cfg(feature = "ssh-agent")]
impl KeyDerivation for SSHAgentParams {
    const INDEX: usize = KeyDerivationMethod::SSHAgent as usize;

    fn lock(
        &mut self,
        content_key: &SymmetricKey,
        secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        // Convert `secret` to a string for the SSH ID.
        let id = String::from_utf8(secret.as_ref().to_vec()).map_err(|_| {
            Error::ssh_agent("SSH Agent secret must be a valid UTF-8 string")
        })?;

        // If None call connect_to_agent to get the agent.
        let agent_box = self
            .agent
            .as_ref()
            .map_or_else(|| connect_to_ssh_agent(), |a| Ok(a.clone()))?;

        // Use the agent directly as SSHAgent trait object
        let agent = agent_box.clone();
        let mut ssh_agent = agent.borrow_mut();

        // List all identities in the SSH agent.
        let ids = ssh_agent.list_identities()?;

        // Filter down to the identities that have Ed25519 keys.
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|k| k.key_data().ed25519().is_some())
            .collect();

        if ids.is_empty() {
            return Err(Error::ssh_agent(
                "No Ed25519 identities available in SSH agent",
            ));
        }

        // If `id` is empty, use the first available identity, otherwise find
        // the one matching `id`.
        let identity = if id.is_empty() {
            // If there is more than one identity, throw an error.
            if ids.len() > 1 {
                return Err(Error::ssh_agent(
                    "Multiple identities available in SSH agent, but no ID provided",
                ));
            }
            // Safe to unwrap because we checked that `ids` is not empty
            ids.first().unwrap()
        } else {
            ids.iter()
                .find(|k| k.comment() == id)
                .ok_or_else(|| Error::ssh_agent("No matching identity found"))?
        };

        // Sign the salt with the identity.
        let salt = self.salt().clone();
        let sig = ssh_agent
            .sign(identity, salt.as_bytes())
            .map_err(|_| Error::ssh_agent("SSH agent refused to sign"))?;

        // Derive the symmetric key using HKDF with HMAC-SHA256.
        let derived_key = SymmetricKey::from_data_ref(hkdf_hmac_sha256(
            &sig,
            &salt,
            SymmetricKey::SYMMETRIC_KEY_SIZE,
        ))
        .unwrap(); // Safe to unwrap because SYMMETRIC_KEY_SIZE is valid.

        // Set the ID in the parameters.
        self.id = id;

        // Encode the method as CBOR data.
        let encoded_method = self.to_cbor_data();

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
        encrypted_message: &EncryptedMessage,
        secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey> {
        // Convert `secret` to a string for the SSH ID.
        let id = String::from_utf8(secret.as_ref().to_vec()).map_err(|_| {
            Error::ssh_agent("SSH Agent secret must be a valid UTF-8 string")
        })?;

        // If None call connect_to_agent to get the agent.
        let agent_box = self
            .agent
            .as_ref()
            .map_or_else(|| connect_to_ssh_agent(), |a| Ok(a.clone()))?;

        // Use the agent directly as SSHAgent trait object
        let agent = agent_box.clone();
        let mut ssh_agent = agent.borrow_mut();

        // List all identities in the SSH agent.
        let ids = ssh_agent.list_identities()?;

        // Filter down to the identities that have Ed25519 keys.
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|k| k.key_data().ed25519().is_some())
            .collect();

        if ids.is_empty() {
            return Err(Error::ssh_agent(
                "No Ed25519 identities available in SSH agent",
            ));
        }

        // id priority:
        // 1. `id` passed in as secret if not empty,
        // 2. `self.id` if not empty,
        // 3. first available identity.
        let identity = if !id.is_empty() {
            ids.iter()
                .find(|k| k.comment() == id)
                .ok_or_else(|| Error::ssh_agent("No matching identity found"))?
        } else if !self.id.is_empty() {
            ids.iter()
                .find(|k| k.comment() == self.id)
                .ok_or_else(|| Error::ssh_agent("No matching identity found"))?
        } else {
            // Safe to unwrap because we checked that `ids` is not empty
            ids.first().unwrap()
        };

        // Sign the salt with the identity.
        let sig = ssh_agent
            .sign(identity, self.salt.as_bytes())
            .map_err(|_| Error::ssh_agent("SSH agent refused to sign"))?;

        // Derive the symmetric key using HKDF with HMAC-SHA256.
        let derived_key = SymmetricKey::from_data_ref(hkdf_hmac_sha256(
            &sig,
            &self.salt,
            SymmetricKey::SYMMETRIC_KEY_SIZE,
        ))
        .unwrap(); // Safe to unwrap because SYMMETRIC_KEY_SIZE is valid.

        // Decrypt the encrypted key with the derived key.
        let decrypted_key =
            derived_key.decrypt(encrypted_message).map_err(|e| {
                Error::crypto(format!(
                    "Failed to decrypt the encrypted key: {}",
                    e
                ))
            })?;

        let content_key = decrypted_key.try_into().map_err(|e| {
            Error::crypto(format!(
                "Failed to convert decrypted key to SymmetricKey: {}",
                e
            ))
        })?;

        // If the decryption was successful, return the symmetric key.
        Ok(content_key)
    }
}

#[cfg(not(feature = "ssh-agent"))]
impl KeyDerivation for SSHAgentParams {
    const INDEX: usize = KeyDerivationMethod::SSHAgent as usize;

    fn lock(
        &mut self,
        _content_key: &SymmetricKey,
        _secret: impl AsRef<[u8]>,
    ) -> Result<EncryptedMessage> {
        Err(Error::general(
            "SSH Agent support not enabled. Recompile with --features ssh-agent",
        ))
    }

    fn unlock(
        &self,
        _encrypted_message: &EncryptedMessage,
        _secret: impl AsRef<[u8]>,
    ) -> Result<SymmetricKey> {
        Err(Error::general(
            "SSH Agent support not enabled. Recompile with --features ssh-agent",
        ))
    }
}

impl std::fmt::Display for SSHAgentParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, r#"SSHAgent("{}")"#, self.id)
    }
}

impl From<SSHAgentParams> for CBOR {
    fn from(val: SSHAgentParams) -> Self {
        vec![
            CBOR::from(SSHAgentParams::INDEX),
            val.salt.into(),
            val.id.into(),
        ]
        .into()
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
        Ok(SSHAgentParams { salt, id, agent: None })
    }
}

#[cfg(all(test, feature = "ssh-agent"))]
mod tests_common {
    use dcbor::prelude::*;

    use super::AgentBox;
    use crate::{
        EncryptedKey, KeyDerivation, KeyDerivationParams, SALT_LEN,
        SSHAgentParams, Salt,
    };

    pub fn test_id() -> String { "your_email@example.com".to_string() }

    pub fn test_ssh_agent_params(agent: AgentBox) {
        // Create SSHAgentParams with the agent.
        let params = SSHAgentParams::new_opt(
            Salt::new_with_len(SALT_LEN).unwrap(),
            "",
            Some(agent.clone()),
        );

        // Create a content key to encrypt.
        let content_key = crate::SymmetricKey::new();

        // Empty: use the first identity in the agent.
        let secret = b"";

        // Lock the content key with the SSH agent parameters.
        let encrypted_key = EncryptedKey::lock_opt(
            KeyDerivationParams::SSHAgent(params),
            secret,
            &content_key,
        )
        .expect("Lock content key with SSH agent params");

        // Serialize the encrypted key to CBOR.
        let cbor_data = encrypted_key.to_cbor_data();

        // Deserialize the CBOR data.
        let cbor = CBOR::try_from_data(cbor_data)
            .expect("Convert encrypted key to CBOR");

        // Convert the CBOR back to an EncryptedKey.
        let encrypted_key_2 = EncryptedKey::try_from_cbor(&cbor)
            .expect("Convert CBOR to EncryptedKey");

        // Extract the SSH agent parameters from the AAD CBOR.
        let aad_cbor = encrypted_key_2
            .aad_cbor()
            .expect("Get AAD CBOR from EncryptedKey");
        let mut params_2 = SSHAgentParams::try_from(aad_cbor)
            .expect("Convert AAD CBOR to SSHAgentParams");

        // Set the mock agent in the parameters.
        params_2.set_agent(Some(agent.clone()));

        // Unlock the content key using the SSH agent parameters.
        let decrypted_content_key =
            params_2.unlock(encrypted_key.encrypted_message(), secret);

        // Assert that the decrypted key matches the original content key.
        assert_eq!(
            content_key,
            decrypted_content_key
                .expect("Unlock content key with SSH agent params")
        );
    }
}

#[cfg(all(test, feature = "ssh-agent"))]
mod mock_agent_tests {
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    use super::{
        AgentBox, SSHAgent,
        tests_common::{test_id, test_ssh_agent_params},
    };
    use crate::{Error, Result};

    struct MockSSHAgent {
        identities: HashMap<String, ssh_key::PrivateKey>,
    }

    impl MockSSHAgent {
        fn new() -> Self { Self { identities: HashMap::new() } }

        fn add_identity(&mut self, key: ssh_key::PrivateKey) {
            self.identities.insert(key.comment().to_string(), key);
        }
    }

    impl SSHAgent for MockSSHAgent {
        fn list_identities(&mut self) -> Result<Vec<ssh_key::PublicKey>> {
            Ok(self
                .identities
                .values()
                .map(|k| k.public_key().clone())
                .collect())
        }

        fn add_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()> {
            self.add_identity(key.clone());
            Ok(())
        }

        fn remove_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()> {
            self.identities.remove(key.comment());
            Ok(())
        }

        fn remove_all_identities(&mut self) -> Result<()> {
            self.identities.clear();
            Ok(())
        }

        fn sign(
            &mut self,
            key: &ssh_key::PublicKey,
            data: &[u8],
        ) -> Result<ssh_key::Signature> {
            let private_key = self
                .identities
                .get(key.comment())
                .ok_or_else(|| Error::ssh_agent("Identity not found"))?;
            let sig: ssh_key::SshSig = private_key
                .sign("test_namespace", ssh_key::HashAlg::Sha256, data)
                .map_err(|e| {
                    Error::ssh_agent(format!("Failed to sign data: {}", e))
                })?;
            Ok(sig.signature().clone())
        }
    }

    fn mock_agent() -> AgentBox {
        let mut agent = MockSSHAgent::new();
        let mut rng = bc_rand::SecureRandomNumberGenerator;
        let keypair: ssh_key::private::Ed25519Keypair =
            ssh_key::private::Ed25519Keypair::random(&mut rng);
        let private_key =
            ssh_key::PrivateKey::new(keypair.into(), test_id()).unwrap();
        agent.add_identity(private_key);
        Rc::new(RefCell::new(agent))
    }

    #[test]
    fn test_mock_agent() {
        let agent = mock_agent();
        let identities = agent.borrow_mut().list_identities().unwrap();
        assert!(!identities.is_empty(), "No identities found in SSH agent");

        let first_identity = &identities[0];
        assert_eq!(first_identity.comment(), test_id());
        let data = b"test data";
        let signature1 = agent.borrow_mut().sign(first_identity, data).unwrap();
        let signature2 = agent.borrow_mut().sign(first_identity, data).unwrap();
        assert_eq!(
            signature1, signature2,
            "Signatures should match for the same data"
        );
    }

    #[test]
    fn test_ssh_agent_params_with_mock_agent() {
        let agent = mock_agent();
        test_ssh_agent_params(agent);
    }
}

/// For these tests to run correctly, you need to have a real SSH agent running
/// and have at least one Ed25519 identity added to it with
/// `your_email@example.com` as the identity comment.
///
/// To run these tests, use the following command:
/// ```bash
/// cargo test real_agent_tests --features ssh_agent_tests
/// ```
///
/// Your `SSH_AUTH_SOCK` environment variable must be set to the socket
/// the SSH agent is listening on. This is usually set automatically when you
/// start your SSH agent, but you can check it with:
/// ```bash
/// echo $SSH_AUTH_SOCK
/// ```
///
/// To list the keys in your SSH agent, you can use:
/// ```bash
/// ssh-add -l
/// ```
///
/// To generate a new Ed25519 key and add it to your SSH agent as a test
/// identity, you can use:
/// ```bash
/// ssh-keygen -t ed25519 -C "your_email@example.com" -f <your_key_file>
/// ssh-add <your_key_file>
/// ```
#[cfg(all(test, feature = "ssh_agent_tests"))]
mod real_agent_tests {
    use dcbor::prelude::*;

    use super::{
        connect_to_ssh_agent,
        tests_common::{test_id, test_ssh_agent_params},
    };
    use crate::{EncryptedKey, KeyDerivationMethod, SymmetricKey};

    pub fn test_content_key() -> SymmetricKey { SymmetricKey::new() }

    #[test]
    #[ignore = "Requires SSH agent with Ed25519 key"]
    fn test_ssh_agent_params_with_real_agent() {
        let agent = connect_to_ssh_agent().expect("Connect to SSH agent");
        test_ssh_agent_params(agent);
    }

    #[test]
    #[ignore = "Requires SSH agent with Ed25519 key"]
    fn test_encrypted_key_ssh_agent_roundtrip() {
        let id = test_id();
        let content_key = test_content_key();

        let encrypted_key = EncryptedKey::lock(
            KeyDerivationMethod::SSHAgent,
            id.clone(),
            &content_key,
        )
        .unwrap();
        let expected = format!(r#"EncryptedKey(SSHAgent("{}"))"#, id);
        assert_eq!(format!("{}", encrypted_key), expected);
        let cbor = encrypted_key.clone().to_cbor();
        let argon2id2 = EncryptedKey::try_from(cbor).unwrap();
        let decrypted = EncryptedKey::unlock(&argon2id2, id).unwrap();

        assert_eq!(content_key, decrypted);
    }

    #[test]
    #[ignore = "Requires SSH agent with Ed25519 key"]
    fn test_encrypted_key_ssh_agent_wrong_secret_fails() {
        let secret = test_id();
        let content_key = test_content_key();
        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::SSHAgent,
            secret,
            &content_key,
        )
        .unwrap();
        let wrong_secret = b"wrong secret";
        let result = EncryptedKey::unlock(&encrypted, wrong_secret);
        assert!(result.is_err(), "Unlock should fail with wrong secret");
    }

    #[test]
    #[ignore = "Requires SSH agent with Ed25519 key"]
    fn test_ssh_agent_lock_fails_with_nonexistent_identity() {
        let secret = b"nonexistent_identity";
        let content_key = test_content_key();
        let encrypted = EncryptedKey::lock(
            KeyDerivationMethod::SSHAgent,
            secret,
            &content_key,
        );
        assert!(
            encrypted.is_err(),
            "Lock should fail with nonexistent identity"
        );
    }
}
