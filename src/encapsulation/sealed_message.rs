use crate::{ tags, Decrypter, EncapsulationCiphertext, EncryptedMessage, Encrypter, Nonce };
use bc_ur::prelude::*;
use anyhow::{ bail, Result, Error };

use super::EncapsulationScheme;

/// A sealed message can be sent to anyone, but only the intended recipient can
/// decrypt it.
#[derive(Clone, PartialEq, Debug)]
pub struct SealedMessage {
    message: EncryptedMessage,
    encapsulated_key: EncapsulationCiphertext,
}

impl SealedMessage {
    /// Creates a new `SealedMessage` from the given plaintext and recipient.
    pub fn new(plaintext: impl Into<Vec<u8>>, recipient: &dyn Encrypter) -> Self {
        Self::new_with_aad(plaintext, recipient, None::<Vec<u8>>)
    }

    /// Creates a new `SealedMessage` from the given plaintext, recipient, and
    /// additional authenticated data.
    pub fn new_with_aad(
        plaintext: impl Into<Vec<u8>>,
        recipient: &dyn Encrypter,
        aad: Option<impl Into<Vec<u8>>>
    ) -> Self {
        Self::new_opt(plaintext, recipient, aad, None::<Nonce>)
    }

    /// Creates a new `SealedMessage` from the given plaintext, recipient, and
    /// additional authenticated data. Also accepts optional test key material
    /// and test nonce.
    pub fn new_opt(
        plaintext: impl Into<Vec<u8>>,
        recipient: &dyn Encrypter,
        aad: Option<impl Into<Vec<u8>>>,
        test_nonce: Option<impl AsRef<Nonce>>
    ) -> Self {
        let (shared_key, encapsulated_key) = recipient.encapsulate_new_shared_secret();
        let message = shared_key.encrypt(plaintext, aad, test_nonce);
        Self {
            message,
            encapsulated_key,
        }
    }

    /// Decrypts the message using the recipient's private key.
    pub fn decrypt(&self, private_key: &dyn Decrypter) -> Result<Vec<u8>> {
        let shared_key = private_key.decapsulate_shared_secret(&self.encapsulated_key)?;
        shared_key.decrypt(&self.message)
    }

    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        self.encapsulated_key.encapsulation_scheme()
    }
}

impl AsRef<SealedMessage> for SealedMessage {
    fn as_ref(&self) -> &SealedMessage {
        self
    }
}

impl CBORTagged for SealedMessage {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SEALED_MESSAGE])
    }
}

impl From<SealedMessage> for CBOR {
    fn from(value: SealedMessage) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for SealedMessage {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedEncodable for SealedMessage {
    fn untagged_cbor(&self) -> CBOR {
        let message: CBOR = self.message.clone().into();
        let ephemeral_public_key: CBOR = self.encapsulated_key.clone().into();
        [message, ephemeral_public_key].into()
    }
}

impl CBORTaggedDecodable for SealedMessage {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        match cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("SealedMessage must have two elements");
                }
                let message = elements[0].clone().try_into()?;
                let ephemeral_public_key = elements[1].clone().try_into()?;
                Ok(Self {
                    message,
                    encapsulated_key: ephemeral_public_key,
                })
            }
            _ => bail!("SealedMessage must be an array"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ EncapsulationScheme, SealedMessage };

    #[test]
    fn test_sealed_message_x25519() {
        let plaintext = b"Some mysteries aren't meant to be solved.";

        let encapsulation = EncapsulationScheme::X25519;
        let (alice_private_key, _) = encapsulation.keypair();
        let (bob_private_key, bob_public_key) = encapsulation.keypair();
        let (carol_private_key, _) = encapsulation.keypair();

        // Alice constructs a message for Bob's eyes only.
        let sealed_message = SealedMessage::new(plaintext, &bob_public_key);

        // Bob decrypts and reads the message.
        assert_eq!(sealed_message.decrypt(&bob_private_key).unwrap(), plaintext);

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_key).is_err());
        assert!(sealed_message.decrypt(&carol_private_key).is_err());
    }

    #[test]
    fn test_sealed_message_kyber512() {
        let plaintext = b"Some mysteries aren't meant to be solved.";

        let encapsulation = EncapsulationScheme::Kyber512;
        let (alice_private_key, _) = encapsulation.keypair();
        let (bob_private_key, bob_public_key) = encapsulation.keypair();
        let (carol_private_key, _) = encapsulation.keypair();

        // Alice constructs a message for Bob's eyes only.
        let sealed_message = SealedMessage::new(plaintext, &bob_public_key);

        // Bob decrypts and reads the message.
        assert_eq!(sealed_message.decrypt(&bob_private_key).unwrap(), plaintext);

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_key).is_err());
        assert!(sealed_message.decrypt(&carol_private_key).is_err());
    }
}
