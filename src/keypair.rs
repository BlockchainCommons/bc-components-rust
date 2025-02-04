use bc_rand::RandomNumberGenerator;
use anyhow::Result;

use crate::{EncapsulationScheme, PrivateKeys, PublicKeys, SignatureScheme};

pub fn keypair() -> (PrivateKeys, PublicKeys) {
    keypair_opt(SignatureScheme::default(), EncapsulationScheme::default())
}

pub fn keypair_using(rng: &mut impl RandomNumberGenerator) -> Result<(PrivateKeys, PublicKeys)> {
    keypair_opt_using(SignatureScheme::default(), EncapsulationScheme::default(), rng)
}

pub fn keypair_opt(signature_scheme: SignatureScheme, encapsulation_scheme: EncapsulationScheme) -> (PrivateKeys, PublicKeys) {
    let (signing_private_key, signing_public_key) = signature_scheme.keypair();
    let (encapsulation_private_key, encapsulation_public_key) = encapsulation_scheme.keypair();
    let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
    let public_keys = PublicKeys::new(signing_public_key, encapsulation_public_key);
    (private_keys, public_keys)
}

pub fn keypair_opt_using(signature_scheme: SignatureScheme, encapsulation_scheme: EncapsulationScheme, rng: &mut impl RandomNumberGenerator) -> Result<(PrivateKeys, PublicKeys)> {
    let (signing_private_key, signing_public_key) = signature_scheme.keypair_using(rng, "")?;
    let (encapsulation_private_key, encapsulation_public_key) = encapsulation_scheme.keypair_using(rng)?;
    let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
    let public_keys = PublicKeys::new(signing_public_key, encapsulation_public_key);
    Ok((private_keys, public_keys))
}
