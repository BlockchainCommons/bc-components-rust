use crate::Kyber;
use crate::{X25519PrivateKey, EncapsulationPrivateKey, EncapsulationPublicKey};


#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Encapsulation {
    X25519,
    Kyber(Kyber),
}

impl Encapsulation {
    pub fn keypair(self) -> (EncapsulationPrivateKey, EncapsulationPublicKey) {
        match self {
            Encapsulation::X25519 => {
                let (private_key, public_key) = X25519PrivateKey::keypair();
                (EncapsulationPrivateKey::X25519(private_key), EncapsulationPublicKey::X25519(public_key))
            }
            Encapsulation::Kyber(level) => {
                let (private_key, public_key) = level.keypair();
                (EncapsulationPrivateKey::Kyber(private_key), EncapsulationPublicKey::Kyber(public_key))
            }
        }
    }
}
