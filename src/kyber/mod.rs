mod kyber_level;
pub use kyber_level::Kyber;

mod kyber_ciphertext;
pub use kyber_ciphertext::KyberCiphertext;

mod kyber_private_key;
pub use kyber_private_key::KyberPrivateKey;

mod kyber_public_key;
pub use kyber_public_key::KyberPublicKey;

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_kyber512() {
        let (private_key, public_key) = Kyber::Kyber512.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 1632);
        assert_eq!(public_key.size(), 800);
        assert_eq!(ciphertext.size(), 768);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_kyber768() {
        let (private_key, public_key) = Kyber::Kyber768.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 2400);
        assert_eq!(public_key.size(), 1184);
        assert_eq!(ciphertext.size(), 1088);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_kyber1024() {
        let (private_key, public_key) = Kyber::Kyber1024.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 3168);
        assert_eq!(public_key.size(), 1568);
        assert_eq!(ciphertext.size(), 1568);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }
}
