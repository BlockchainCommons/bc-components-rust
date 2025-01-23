mod dilithium_level;
pub use dilithium_level::Dilithium;

mod dilithium_private_key;
pub use dilithium_private_key::DilithiumPrivateKey;

mod dilithium_public_key;
pub use dilithium_public_key::DilithiumPublicKey;

mod dilithium_signature;
pub use dilithium_signature::DilithiumSignature;

#[cfg(test)]
mod tests {
    use crate::Dilithium;

    const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_dilithium2_signing() {
        let (public_key, private_key) = Dilithium::Dilithium2.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key.verify(&signature, &MESSAGE[..MESSAGE.len() - 1]).unwrap());
    }

    #[test]
    fn test_dilithium3_signing() {
        let (public_key, private_key) = Dilithium::Dilithium3.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key.verify(&signature, &MESSAGE[..MESSAGE.len() - 1]).unwrap());
    }

    #[test]
    fn test_dilithium5_signing() {
        let (public_key, private_key) = Dilithium::Dilithium5.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key.verify(&signature, &MESSAGE[..MESSAGE.len() - 1]).unwrap());
    }
}
