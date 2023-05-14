pub mod tags;

mod digest;
mod salt;
pub use digest::Digest;

mod digest_provider;
pub use digest_provider::DigestProvider;

mod compressed;
pub use compressed::Compressed;

mod nonce;
pub use nonce::Nonce;

mod encrypted_message;
pub use encrypted_message::EncryptedMessage;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn tags() {
        assert_eq!(tags::LEAF.value(), 24);
        assert_eq!(tags::LEAF.name().as_ref().unwrap(), Some("leaf").unwrap());
    }
}
