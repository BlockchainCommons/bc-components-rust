use crate::{ EncryptedMessage, AgreementPublicKey, PublicKeyBase, PrivateKeyBase, Nonce, tags };
use bc_ur::prelude::*;
use anyhow::{ bail, Result, Error };

/// A sealed message can be sent to anyone, but only the intended recipient can
/// decrypt it.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SealedMessage {
    message: EncryptedMessage,
    ephemeral_public_key: AgreementPublicKey,
}

impl SealedMessage {
    /// Creates a new `SealedMessage` from the given plaintext and recipient.
    pub fn new(plaintext: impl Into<Vec<u8>>, recipient: &PublicKeyBase) -> Self {
        Self::new_with_aad(plaintext, recipient, None::<Vec<u8>>)
    }

    /// Creates a new `SealedMessage` from the given plaintext, recipient, and
    /// additional authenticated data.
    pub fn new_with_aad(
        plaintext: impl Into<Vec<u8>>,
        recipient: &PublicKeyBase,
        aad: Option<impl Into<Vec<u8>>>
    ) -> Self {
        Self::new_opt(plaintext, recipient, aad, None::<Vec<u8>>, None::<Nonce>)
    }

    /// Creates a new `SealedMessage` from the given plaintext, recipient, and
    /// additional authenticated data. Also accepts optional test key material
    /// and test nonce.
    pub fn new_opt(
        plaintext: impl Into<Vec<u8>>,
        recipient: &PublicKeyBase,
        aad: Option<impl Into<Vec<u8>>>,
        test_key_material: Option<impl Into<Vec<u8>>>,
        test_nonce: Option<impl AsRef<Nonce>>
    ) -> Self {
        let ephemeral_sender = PrivateKeyBase::from_optional_data(test_key_material);
        let recipient_public_key = recipient.agreement_public_key();
        let shared_key = ephemeral_sender
            .agreement_private_key()
            .shared_key_with(recipient_public_key);
        let message = shared_key.encrypt(plaintext, aad, test_nonce);
        let ephemeral_public_key = ephemeral_sender.agreement_private_key().public_key();
        Self {
            message,
            ephemeral_public_key,
        }
    }

    /// Decrypts the message using the recipient's private key.
    pub fn decrypt(&self, private_key: &PrivateKeyBase) -> Result<Vec<u8>, bc_crypto::Error> {
        let shared_key = private_key
            .agreement_private_key()
            .shared_key_with(&self.ephemeral_public_key);
        shared_key.decrypt(&self.message)
    }
}

impl AsRef<SealedMessage> for SealedMessage {
    fn as_ref(&self) -> &SealedMessage {
        self
    }
}

impl CBORTagged for SealedMessage {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SEALED_MESSAGE]
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
        let ephemeral_public_key: CBOR = self.ephemeral_public_key.clone().into();
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
                    ephemeral_public_key,
                })
            }
            _ => bail!("SealedMessage must be an array"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ SealedMessage, PrivateKeyBase };
    use hex_literal::hex;

    #[test]
    fn test_sealed_message() {
        let plaintext = b"Some mysteries aren't meant to be solved.";

        let alice_seed = &hex!("82f32c855d3d542256180810797e0073");
        let alice_private_key = PrivateKeyBase::from_data(alice_seed);
        // let alice_public_key = alice_private_key.public_key();

        let bob_seed = &hex!("187a5973c64d359c836eba466a44db7b");
        let bob_private_key = PrivateKeyBase::from_data(bob_seed);
        let bob_public_key = bob_private_key.schnorr_public_key_base();

        let carol_seed = &hex!("8574afab18e229651c1be8f76ffee523");
        let carol_private_key = PrivateKeyBase::from_data(carol_seed);
        // let carol_public_key = carol_private_key.public_key();

        // Alice constructs a message for Bob's eyes only.
        let sealed_message = SealedMessage::new(plaintext, &bob_public_key);

        // Bob decrypts and reads the message.
        assert_eq!(sealed_message.decrypt(&bob_private_key).unwrap(), plaintext);

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_key).is_err());
        assert!(sealed_message.decrypt(&carol_private_key).is_err());
    }
}
