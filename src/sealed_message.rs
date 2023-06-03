use crate::{EncryptedMessage, AgreementPublicKey, PublicKeyBase, PrivateKeyBase, Nonce};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SealedMessage {
    message: EncryptedMessage,
    ephemeral_public_key: AgreementPublicKey,
}

impl SealedMessage {
    pub fn new<D>(
        plaintext: D,
        recipient: &PublicKeyBase,
        aad: Option<&[u8]>,
        test_key_material: Option<&[u8]>,
        test_nonce: Option<Nonce>
    ) -> Self
    where D: AsRef<[u8]>
    {
        let ephemeral_sender = PrivateKeyBase::from_optional_data(test_key_material);
        let recipient_public_key = recipient.agreement_public_key();
        let shared_key = ephemeral_sender.agreement_private_key().shared_key_with(recipient_public_key);
        let message = shared_key.encrypt(plaintext, aad, test_nonce);
        let ephemeral_public_key = ephemeral_sender.agreement_private_key().public_key();
        Self {
            message,
            ephemeral_public_key,
        }
    }

    pub fn decrypt(&self, private_keys: &PrivateKeyBase) -> Result<Vec<u8>, bc_crypto::Error> {
        let shared_key = private_keys.agreement_private_key().shared_key_with(&self.ephemeral_public_key);
        shared_key.decrypt(&self.message)
    }
}

/*
```swift
    func testSealedMessage() throws {
        // Alice constructs a message for Bob's eyes only.
        let sealedMessage = SealedMessage(plaintext: plaintextMysteries, recipient: bobPublicKeys)

        // Bob decrypts and reads the message.
        XCTAssertEqual(try sealedMessage.decrypt(with: bobPrivateKeys), plaintextMysteries.utf8Data)

        // No one else can decrypt the message, not even the sender.
        XCTAssertThrowsError(try sealedMessage.decrypt(with: alicePrivateKeys))
        XCTAssertThrowsError(try sealedMessage.decrypt(with: carolPrivateKeys))
    }
```
 */

#[cfg(test)]
mod tests {
    use crate::{SealedMessage, PrivateKeyBase};
    use hex_literal::hex;

    #[test]
    fn test_sealed_message() {
        let plaintext = "Some mysteries aren't meant to be solved.".as_bytes();

        let alice_seed = hex!("82f32c855d3d542256180810797e0073");
        let alice_private_keys = PrivateKeyBase::from_data(&alice_seed);
        // let alice_public_keys = alice_private_keys.public_keys();

        let bob_seed = hex!("187a5973c64d359c836eba466a44db7b");
        let bob_private_keys = PrivateKeyBase::from_data(&bob_seed);
        let bob_public_keys = bob_private_keys.public_keys();

        let carol_seed = hex!("8574afab18e229651c1be8f76ffee523");
        let carol_private_keys = PrivateKeyBase::from_data(&carol_seed);
        // let carol_public_keys = carol_private_keys.public_keys();

        // Alice constructs a message for Bob's eyes only.
        let sealed_message = SealedMessage::new(plaintext, &bob_public_keys, None, None, None);

        // Bob decrypts and reads the message.
        assert_eq!(sealed_message.decrypt(&bob_private_keys).unwrap(), plaintext);

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_keys).is_err());
        assert!(sealed_message.decrypt(&carol_private_keys).is_err());
    }
}
