mod mlkem_level;
pub use mlkem_level::MLKEM;

mod mlkem_ciphertext;
pub use mlkem_ciphertext::MLKEMCiphertext;

mod mlkem_private_key;
pub use mlkem_private_key::MLKEMPrivateKey;

mod mlkem_public_key;
pub use mlkem_public_key::MLKEMPublicKey;

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_mlkem512() {
        let (private_key, public_key) = MLKEM::MLKEM512.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 1632);
        assert_eq!(public_key.size(), 800);
        assert_eq!(ciphertext.size(), 768);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_mlkem768() {
        let (private_key, public_key) = MLKEM::MLKEM768.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 2400);
        assert_eq!(public_key.size(), 1184);
        assert_eq!(ciphertext.size(), 1088);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_mlkem1024() {
        let (private_key, public_key) = MLKEM::MLKEM1024.keypair();
        let (shared_secret_1, ciphertext) = public_key.encapsulate_new_shared_secret();
        assert_eq!(private_key.size(), 3168);
        assert_eq!(public_key.size(), 1568);
        assert_eq!(ciphertext.size(), 1568);
        let shared_secret_2 = private_key.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(shared_secret_1, shared_secret_2);
    }
}
