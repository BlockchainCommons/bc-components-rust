mod digest;
pub use digest::Digest;

mod cid;
pub use cid::CID;

mod digest_provider;
pub use digest_provider::DigestProvider;

mod compressed;
pub use compressed::Compressed;

mod nonce;
pub use nonce::Nonce;

mod symmetric_key;
pub use symmetric_key::SymmetricKey;

mod encrypted_message;
pub use encrypted_message::EncryptedMessage;

mod salt;
pub use salt::Salt;

mod uri;
pub use uri::URI;

mod uuid;
pub use uuid::UUID;

pub mod tags_registry;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn tags() {
        assert_eq!(tags_registry::LEAF.value(), 24);
        assert_eq!(tags_registry::LEAF.name().as_ref().unwrap(), Some("leaf").unwrap());
    }
}
