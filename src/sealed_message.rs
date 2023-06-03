use crate::{EncryptedMessage, AgreementPublicKey, PublicKeyBase, PrivateKeyBase, Nonce};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SealedMessage {
    message: EncryptedMessage,
    ephemeral_public_key: AgreementPublicKey,
}

impl SealedMessage {
    pub fn new<D1, D2>(
        plaintext: D1,
        recipient: &PublicKeyBase,
        aad: Option<&[u8]>,
        test_key_material: Option<D2>,
        test_nonce: Option<Nonce>
    ) -> Self
    where D1: AsRef<[u8]>,
          D2: AsRef<[u8]>
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
