mod mldsa_level;
pub use mldsa_level::MLDSA;

mod mldsa_private_key;
pub use mldsa_private_key::MLDSAPrivateKey;

mod mldsa_public_key;
pub use mldsa_public_key::MLDSAPublicKey;

mod mldsa_signature;
pub use mldsa_signature::MLDSASignature;

#[cfg(test)]
mod tests {
    use crate::MLDSA;

    const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_mldsa44_signing() {
        let (private_key, public_key) = MLDSA::MLDSA44.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key
            .verify(&signature, &MESSAGE[..MESSAGE.len() - 1])
            .unwrap());
    }

    #[test]
    fn test_mldsa65_signing() {
        let (private_key, public_key) = MLDSA::MLDSA65.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key
            .verify(&signature, &MESSAGE[..MESSAGE.len() - 1])
            .unwrap());
    }

    #[test]
    fn test_mldsa87_signing() {
        let (private_key, public_key) = MLDSA::MLDSA87.keypair();
        let signature = private_key.sign(MESSAGE);
        assert!(public_key.verify(&signature, MESSAGE).unwrap());
        assert!(!public_key
            .verify(&signature, &MESSAGE[..MESSAGE.len() - 1])
            .unwrap());
    }
}
