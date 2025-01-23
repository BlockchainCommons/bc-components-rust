mod encapsulation_type;
pub use encapsulation_type::Encapsulation;

mod encapsulation_private_key;
pub use encapsulation_private_key::EncapsulationPrivateKey;

mod encapsulation_public_key;
pub use encapsulation_public_key::EncapsulationPublicKey;

mod encapsulation_ciphertext;
pub use encapsulation_ciphertext::EncapsulationCiphertext;

mod sealed_message;
pub use sealed_message::SealedMessage;

#[cfg(test)]
mod tests {
    use crate::{Encapsulation, Kyber};

    #[test]
    fn test_x25519() {
        let (private_key, public_key) = Encapsulation::X25519.keypair();
        let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
        let secret2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_kyber512() {
        let (private_key, public_key) = Encapsulation::Kyber(Kyber::Kyber512).keypair();
        let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
        let secret2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_kyber768() {
        let (private_key, public_key) = Encapsulation::Kyber(Kyber::Kyber768).keypair();
        let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
        let secret2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_kyber1024() {
        let (private_key, public_key) = Encapsulation::Kyber(Kyber::Kyber1024).keypair();
        let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
        let secret2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }
}
