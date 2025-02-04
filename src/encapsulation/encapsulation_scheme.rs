use anyhow::{bail, Result};
use bc_rand::RandomNumberGenerator;

use crate::Kyber;
use crate::{X25519PrivateKey, EncapsulationPrivateKey, EncapsulationPublicKey};

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum EncapsulationScheme {
    #[default]
    X25519,
    Kyber512,
    Kyber768,
    Kyber1024,
}

impl EncapsulationScheme {
    pub fn keypair(self) -> (EncapsulationPrivateKey, EncapsulationPublicKey) {
        match self {
            EncapsulationScheme::X25519 => {
                let (private_key, public_key) = X25519PrivateKey::keypair();
                (EncapsulationPrivateKey::X25519(private_key), EncapsulationPublicKey::X25519(public_key))
            }
            EncapsulationScheme::Kyber512 => {
                let (private_key, public_key) = Kyber::Kyber512.keypair();
                (EncapsulationPrivateKey::Kyber(private_key), EncapsulationPublicKey::Kyber(public_key))
            }
            EncapsulationScheme::Kyber768 => {
                let (private_key, public_key) = Kyber::Kyber768.keypair();
                (EncapsulationPrivateKey::Kyber(private_key), EncapsulationPublicKey::Kyber(public_key))
            }
            EncapsulationScheme::Kyber1024 => {
                let (private_key, public_key) = Kyber::Kyber1024.keypair();
                (EncapsulationPrivateKey::Kyber(private_key), EncapsulationPublicKey::Kyber(public_key))
            }
        }
    }

    pub fn keypair_using(self, rng: &mut impl RandomNumberGenerator) -> Result<(EncapsulationPrivateKey, EncapsulationPublicKey)> {
        match self {
            EncapsulationScheme::X25519 => {
                let (private_key, public_key) = X25519PrivateKey::keypair_using(rng);
                Ok((EncapsulationPrivateKey::X25519(private_key), EncapsulationPublicKey::X25519(public_key)))
            }
            _ => bail!("Deterministic keypair generation not supported for this encapsulation scheme"),
        }
    }
}
