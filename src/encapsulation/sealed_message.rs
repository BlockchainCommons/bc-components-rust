use anyhow::Result;
use bc_ur::prelude::*;

use super::EncapsulationScheme;
use crate::{
    Decrypter, EncapsulationCiphertext, EncryptedMessage, Encrypter, Nonce,
    tags,
};

/// A sealed message that can only be decrypted by the intended recipient.
///
/// `SealedMessage` provides a public key encryption mechanism where a message
/// is encrypted with a symmetric key, and that key is then encapsulated using
/// the recipient's public key. This ensures that only the recipient can decrypt
/// the message by first decapsulating the shared secret using their private
/// key.
///
/// Features:
/// - Anonymous sender: The sender's identity is not revealed in the sealed
///   message
/// - Authenticated encryption: Message integrity and authenticity are
///   guaranteed
/// - Forward secrecy: Each message uses a different ephemeral key
/// - Post-quantum security options: Can use ML-KEM for quantum-resistant
///   encryption
///
/// The structure internally contains:
/// - An `EncryptedMessage` containing the actual encrypted data
/// - An `EncapsulationCiphertext` containing the encapsulated shared secret
#[derive(Clone, PartialEq, Debug)]
pub struct SealedMessage {
    /// The encrypted message content
    message: EncryptedMessage,
    /// The encapsulated key used to encrypt the message
    encapsulated_key: EncapsulationCiphertext,
}

impl SealedMessage {
    /// Creates a new `SealedMessage` from the given plaintext and recipient.
    ///
    /// This method performs the following steps:
    /// 1. Generates a new shared secret key and encapsulates it for the
    ///    recipient
    /// 2. Encrypts the plaintext using that shared secret
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The message data to encrypt
    /// * `recipient` - The recipient who will be able to decrypt the message
    ///
    /// # Returns
    ///
    /// A new `SealedMessage` containing the encrypted message and encapsulated
    /// key
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{EncapsulationScheme, SealedMessage};
    ///
    /// // Generate a keypair for the recipient
    /// let (recipient_private_key, recipient_public_key) =
    ///     EncapsulationScheme::default().keypair();
    ///
    /// // Create a sealed message for the recipient
    /// let plaintext = b"For your eyes only";
    /// let sealed_message = SealedMessage::new(plaintext, &recipient_public_key);
    ///
    /// // The recipient can decrypt the message
    /// let decrypted = sealed_message.decrypt(&recipient_private_key).unwrap();
    /// assert_eq!(decrypted, plaintext);
    /// ```
    pub fn new(plaintext: impl AsRef<[u8]>, recipient: &dyn Encrypter) -> Self {
        Self::new_with_aad(plaintext, recipient, None::<Vec<u8>>)
    }

    /// Creates a new `SealedMessage` with additional authenticated data (AAD).
    ///
    /// AAD is data that is authenticated but not encrypted. It can be used to
    /// bind the encrypted message to some context.
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The message data to encrypt
    /// * `recipient` - The recipient who will be able to decrypt the message
    /// * `aad` - Additional authenticated data that will be bound to the
    ///   encryption
    ///
    /// # Returns
    ///
    /// A new `SealedMessage` containing the encrypted message and encapsulated
    /// key
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{EncapsulationScheme, SealedMessage};
    ///
    /// // Generate a keypair for the recipient
    /// let (recipient_private_key, recipient_public_key) =
    ///     EncapsulationScheme::default().keypair();
    ///
    /// // Create a sealed message with additional authenticated data
    /// let plaintext = b"For your eyes only";
    /// let aad = b"Message ID: 12345";
    /// let sealed_message = SealedMessage::new_with_aad(
    ///     plaintext,
    ///     &recipient_public_key,
    ///     Some(aad),
    /// );
    ///
    /// // The recipient can decrypt the message
    /// let decrypted = sealed_message.decrypt(&recipient_private_key).unwrap();
    /// assert_eq!(decrypted, plaintext);
    /// ```
    pub fn new_with_aad(
        plaintext: impl AsRef<[u8]>,
        recipient: &dyn Encrypter,
        aad: Option<impl AsRef<[u8]>>,
    ) -> Self {
        Self::new_opt(plaintext, recipient, aad, None::<Nonce>)
    }

    /// Creates a new `SealedMessage` with options for testing.
    ///
    /// This method is similar to `new_with_aad` but allows specifying a test
    /// nonce, which is useful for deterministic testing.
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The message data to encrypt
    /// * `recipient` - The recipient who will be able to decrypt the message
    /// * `aad` - Additional authenticated data that will be bound to the
    ///   encryption
    /// * `test_nonce` - Optional nonce for deterministic encryption (testing
    ///   only)
    ///
    /// # Returns
    ///
    /// A new `SealedMessage` containing the encrypted message and encapsulated
    /// key
    pub fn new_opt(
        plaintext: impl AsRef<[u8]>,
        recipient: &dyn Encrypter,
        aad: Option<impl AsRef<[u8]>>,
        test_nonce: Option<impl AsRef<Nonce>>,
    ) -> Self {
        let (shared_key, encapsulated_key) =
            recipient.encapsulate_new_shared_secret();
        let message = shared_key.encrypt(plaintext, aad, test_nonce);
        Self { message, encapsulated_key }
    }

    /// Decrypts the message using the recipient's private key.
    ///
    /// This method performs the following steps:
    /// 1. Decapsulates the shared secret using the recipient's private key
    /// 2. Uses the shared secret to decrypt the message
    ///
    /// # Parameters
    ///
    /// * `private_key` - The private key of the intended recipient
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted message data if successful,
    /// or an error if decryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The private key doesn't match the one used for encapsulation
    /// - The decapsulation process fails
    /// - The decryption process fails (e.g., message tampering)
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{EncapsulationScheme, SealedMessage};
    ///
    /// // Generate keypairs for different users
    /// let (alice_private_key, _) = EncapsulationScheme::default().keypair();
    /// let (bob_private_key, bob_public_key) =
    ///     EncapsulationScheme::default().keypair();
    ///
    /// // Alice sends a message to Bob
    /// let plaintext = b"Secret message for Bob";
    /// let sealed_message = SealedMessage::new(plaintext, &bob_public_key);
    ///
    /// // Bob can decrypt the message
    /// let decrypted = sealed_message.decrypt(&bob_private_key).unwrap();
    /// assert_eq!(decrypted, plaintext);
    ///
    /// // Alice cannot decrypt the message she sent
    /// assert!(sealed_message.decrypt(&alice_private_key).is_err());
    /// ```
    pub fn decrypt(&self, private_key: &dyn Decrypter) -> Result<Vec<u8>> {
        let shared_key =
            private_key.decapsulate_shared_secret(&self.encapsulated_key)?;
        shared_key.decrypt(&self.message)
    }

    /// Returns the encapsulation scheme used for this sealed message.
    ///
    /// # Returns
    ///
    /// The encapsulation scheme (X25519, MLKEM512, MLKEM768, or MLKEM1024)
    /// that was used to create this sealed message.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::{EncapsulationScheme, SealedMessage};
    ///
    /// // Generate a keypair using ML-KEM768
    /// let (_, public_key) = EncapsulationScheme::MLKEM768.keypair();
    ///
    /// // Create a sealed message
    /// let sealed_message =
    ///     SealedMessage::new(b"Quantum-resistant message", &public_key);
    ///
    /// // Check the encapsulation scheme
    /// assert_eq!(
    ///     sealed_message.encapsulation_scheme(),
    ///     EncapsulationScheme::MLKEM768
    /// );
    /// ```
    pub fn encapsulation_scheme(&self) -> EncapsulationScheme {
        self.encapsulated_key.encapsulation_scheme()
    }
}

/// Implementation of `AsRef` trait for `SealedMessage`.
impl AsRef<SealedMessage> for SealedMessage {
    fn as_ref(&self) -> &SealedMessage { self }
}

/// Implementation of CBOR tagging for `SealedMessage`.
impl CBORTagged for SealedMessage {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_SEALED_MESSAGE]) }
}

/// Conversion from `SealedMessage` to CBOR for serialization.
impl From<SealedMessage> for CBOR {
    fn from(value: SealedMessage) -> Self { value.tagged_cbor() }
}

/// Conversion from CBOR to `SealedMessage` for deserialization.
impl TryFrom<CBOR> for SealedMessage {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implementation of CBOR encoding for `SealedMessage`.
impl CBORTaggedEncodable for SealedMessage {
    fn untagged_cbor(&self) -> CBOR {
        let message: CBOR = self.message.clone().into();
        let ephemeral_public_key: CBOR = self.encapsulated_key.clone().into();
        [message, ephemeral_public_key].into()
    }
}

/// Implementation of CBOR decoding for `SealedMessage`.
impl CBORTaggedDecodable for SealedMessage {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        match cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("SealedMessage must have two elements".into());
                }
                let message = elements[0].clone().try_into()?;
                let ephemeral_public_key = elements[1].clone().try_into()?;
                Ok(Self { message, encapsulated_key: ephemeral_public_key })
            }
            _ => Err("SealedMessage must be an array".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{EncapsulationScheme, SealedMessage};

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
        assert_eq!(
            sealed_message.decrypt(&bob_private_key).unwrap(),
            plaintext
        );

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_key).is_err());
        assert!(sealed_message.decrypt(&carol_private_key).is_err());
    }

    #[test]
    fn test_sealed_message_mlkem512() {
        let plaintext = b"Some mysteries aren't meant to be solved.";

        let encapsulation = EncapsulationScheme::MLKEM512;
        let (alice_private_key, _) = encapsulation.keypair();
        let (bob_private_key, bob_public_key) = encapsulation.keypair();
        let (carol_private_key, _) = encapsulation.keypair();

        // Alice constructs a message for Bob's eyes only.
        let sealed_message = SealedMessage::new(plaintext, &bob_public_key);

        // Bob decrypts and reads the message.
        assert_eq!(
            sealed_message.decrypt(&bob_private_key).unwrap(),
            plaintext
        );

        // No one else can decrypt the message, not even the sender.
        assert!(sealed_message.decrypt(&alice_private_key).is_err());
        assert!(sealed_message.decrypt(&carol_private_key).is_err());
    }
}
