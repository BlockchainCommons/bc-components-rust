mod encapsulation_scheme;
pub use encapsulation_scheme::EncapsulationScheme;

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
    use crate::EncapsulationScheme;

    fn test_encapsulation(encapsulation: EncapsulationScheme) {
        let (private_key, public_key) = encapsulation.keypair();
        let (secret1, ciphertext) = public_key.encapsulate_new_shared_secret();
        let secret2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_x25519() {
        test_encapsulation(EncapsulationScheme::X25519);
    }

    #[test]
    fn test_kyber512() {
        test_encapsulation(EncapsulationScheme::Kyber512);
    }

    #[test]
    fn test_kyber768() {
        test_encapsulation(EncapsulationScheme::Kyber768);
    }

    #[test]
    fn test_kyber1024() {
        test_encapsulation(EncapsulationScheme::Kyber1024);
    }
}
