mod argon2id_params;
pub use argon2id_params::Argon2idParams;
mod hkdf_params;
pub use hkdf_params::HKDFParams;
mod pbkdf2_params;
pub use pbkdf2_params::PBKDF2Params;
mod scrypt_params;
pub use scrypt_params::ScryptParams;
mod hash_type;
pub use hash_type::HashType;
mod key_derivation;
pub use key_derivation::KeyDerivation;
mod key_derivation_params;
pub use key_derivation_params::KeyDerivationParams;
mod key_derivation_method;
pub use key_derivation_method::KeyDerivationMethod;
mod encrypted_key_impl;
pub use encrypted_key_impl::EncryptedKey;
#[cfg(feature = "ssh-agent")]
mod ssh_agent_params;
#[cfg(feature = "ssh-agent")]
pub use ssh_agent_params::SSHAgentParams;
#[cfg(feature = "ssh-agent")]
pub use ssh_agent_params::{SSHAgent, connect_to_ssh_agent};

pub const SALT_LEN: usize = 16;
