use anyhow::{bail, Result};
use bc_rand::RandomNumberGenerator;

use crate::MLKEM;
use crate::{EncapsulationPrivateKey, EncapsulationPublicKey, X25519PrivateKey};

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum EncapsulationScheme {
    #[default]
    X25519,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
}

impl EncapsulationScheme {
    pub fn keypair(self) -> (EncapsulationPrivateKey, EncapsulationPublicKey) {
        match self {
            EncapsulationScheme::X25519 => {
                let (private_key, public_key) = X25519PrivateKey::keypair();
                (
                    EncapsulationPrivateKey::X25519(private_key),
                    EncapsulationPublicKey::X25519(public_key),
                )
            }
            EncapsulationScheme::MLKEM512 => {
                let (private_key, public_key) = MLKEM::MLKEM512.keypair();
                (
                    EncapsulationPrivateKey::MLKEM(private_key),
                    EncapsulationPublicKey::MLKEM(public_key),
                )
            }
            EncapsulationScheme::MLKEM768 => {
                let (private_key, public_key) = MLKEM::MLKEM768.keypair();
                (
                    EncapsulationPrivateKey::MLKEM(private_key),
                    EncapsulationPublicKey::MLKEM(public_key),
                )
            }
            EncapsulationScheme::MLKEM1024 => {
                let (private_key, public_key) = MLKEM::MLKEM1024.keypair();
                (
                    EncapsulationPrivateKey::MLKEM(private_key),
                    EncapsulationPublicKey::MLKEM(public_key),
                )
            }
        }
    }

    pub fn keypair_using(
        self,
        rng: &mut impl RandomNumberGenerator,
    ) -> Result<(EncapsulationPrivateKey, EncapsulationPublicKey)> {
        match self {
            EncapsulationScheme::X25519 => {
                let (private_key, public_key) = X25519PrivateKey::keypair_using(rng);
                Ok((
                    EncapsulationPrivateKey::X25519(private_key),
                    EncapsulationPublicKey::X25519(public_key),
                ))
            }
            _ => bail!(
                "Deterministic keypair generation not supported for this encapsulation scheme"
            ),
        }
    }
}
