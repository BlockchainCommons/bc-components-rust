use crate::{EncryptedMessage, AgreementPublicKey, PublicKeyBase, PrivateKeyBase, Nonce, tags};

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORDecodable, CBORCodable, CBORTaggedEncodable, CBORTaggedDecodable, CBORTaggedCodable};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SealedMessage {
    message: EncryptedMessage,
    ephemeral_public_key: AgreementPublicKey,
}

impl SealedMessage {
    pub fn new<D>(plaintext: D, recipient: &PublicKeyBase) -> Self
    where
        D: AsRef<[u8]>
    {
        Self::new_with_aad(plaintext, recipient, None)
    }

    pub fn new_with_aad<D>(plaintext: D, recipient: &PublicKeyBase, aad: Option<&[u8]>) -> Self
    where
        D: AsRef<[u8]>
    {
        Self::new_opt(plaintext, recipient, aad, None, None::<Nonce>)
    }

    pub fn new_opt<D, N>(
        plaintext: D,
        recipient: &PublicKeyBase,
        aad: Option<&[u8]>,
        test_key_material: Option<&[u8]>,
        test_nonce: Option<N>
    ) -> Self
    where
        D: AsRef<[u8]>,
        N: AsRef<Nonce>,
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

impl CBORTagged for SealedMessage {
    const CBOR_TAG: Tag = tags::SEALED_MESSAGE;
}

impl CBOREncodable for SealedMessage {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORDecodable for SealedMessage {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORCodable for SealedMessage { }

impl CBORTaggedEncodable for SealedMessage {
    fn untagged_cbor(&self) -> CBOR {
        let message = self.message.cbor();
        let ephemeral_public_key = self.ephemeral_public_key.cbor();
        [message, ephemeral_public_key].cbor()
    }
}

impl CBORTaggedDecodable for SealedMessage {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        match cbor {
            CBOR::Array(elements) => {
                if elements.len() != 2 {
                    return Err(dcbor::Error::InvalidFormat);
                }
                let message = EncryptedMessage::from_cbor(&elements[0])?;
                let ephemeral_public_key = AgreementPublicKey::from_cbor(&elements[1])?;
                Ok(Self {
                    message,
                    ephemeral_public_key,
                })
            },
            _ => Err(dcbor::Error::InvalidFormat),
        }
    }
}

impl CBORTaggedCodable for SealedMessage { }

impl UREncodable for SealedMessage { }

impl URDecodable for SealedMessage { }

impl URCodable for SealedMessage { }

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
        let sealed_message = SealedMessage::new(plaintext, &bob_public_keys);

        // Bob decrypts and reads the message.
        assert_eq!(sealed_message.decrypt(&bob_private_keys).unwrap(), plaintext);

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_keys).is_err());
        assert!(sealed_message.decrypt(&carol_private_keys).is_err());
    }
}
