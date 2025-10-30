use bc_rand::RandomNumberGenerator;

use crate::{
    EncapsulationScheme, PrivateKeys, PublicKeys, Result, SignatureScheme,
};

/// Generates a key pair using the default signature and encapsulation schemes.
///
/// This function creates a new key pair containing both signing and
/// encapsulation (encryption) keys using the default cryptographic schemes:
/// - Default signature scheme: Currently `SignatureScheme::Schnorr`
/// - Default encapsulation scheme: Currently `EncapsulationScheme::X25519`
///
/// # Returns
///
/// A tuple containing:
/// - `PrivateKeys`: The private keys for signing and encapsulation
/// - `PublicKeys`: The corresponding public keys
///
/// # Example
///
/// ```
/// use bc_components::keypair;
///
/// // Generate a key pair with default cryptographic schemes
/// let (private_keys, public_keys) = keypair();
///
/// // The private_keys can be used for signing and decryption
/// // The public_keys can be shared and used for verification and encryption
/// ```
pub fn keypair() -> (PrivateKeys, PublicKeys) {
    keypair_opt(SignatureScheme::default(), EncapsulationScheme::default())
}

/// Generates a key pair using the default schemes and a custom random number
/// generator.
///
/// This function creates a deterministic key pair using the provided random
/// number generator and the default cryptographic schemes.
///
/// # Parameters
///
/// * `rng` - A mutable reference to a random number generator
///
/// # Returns
///
/// A Result containing a tuple with `PrivateKeys` and `PublicKeys` if
/// successful, or an error if key generation fails.
///
/// # Errors
///
/// Returns an error if either the signature or encapsulation key generation
/// fails.
///
/// # Example
///
/// ```
/// use bc_components::keypair_using;
/// use bc_rand::SecureRandomNumberGenerator;
///
/// // Create a random number generator
/// let mut rng = SecureRandomNumberGenerator;
///
/// // Generate a key pair with default schemes but custom RNG
/// let result = keypair_using(&mut rng);
/// assert!(result.is_ok());
/// ```
pub fn keypair_using(
    rng: &mut impl RandomNumberGenerator,
) -> Result<(PrivateKeys, PublicKeys)> {
    keypair_opt_using(
        SignatureScheme::default(),
        EncapsulationScheme::default(),
        rng,
    )
}

/// Generates a key pair with specified signature and encapsulation schemes.
///
/// This function creates a new key pair with custom cryptographic schemes for
/// both signing and encryption operations.
///
/// # Parameters
///
/// * `signature_scheme` - The signature scheme to use (e.g., Schnorr, ECDSA,
///   Ed25519)
/// * `encapsulation_scheme` - The key encapsulation scheme to use (e.g.,
///   X25519, ML-KEM)
///
/// # Returns
///
/// A tuple containing:
/// - `PrivateKeys`: The private keys for signing and encapsulation
/// - `PublicKeys`: The corresponding public keys
///
/// # Example
///
/// ```ignore
/// use bc_components::{EncapsulationScheme, SignatureScheme, keypair_opt};
///
/// // Generate a key pair with Ed25519 for signing and ML-KEM768 for encryption
/// let (private_keys, public_keys) =
///     keypair_opt(SignatureScheme::Ed25519, EncapsulationScheme::MLKEM768);
/// ```
pub fn keypair_opt(
    signature_scheme: SignatureScheme,
    encapsulation_scheme: EncapsulationScheme,
) -> (PrivateKeys, PublicKeys) {
    let (signing_private_key, signing_public_key) = signature_scheme.keypair();
    let (encapsulation_private_key, encapsulation_public_key) =
        encapsulation_scheme.keypair();
    let private_keys =
        PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
    let public_keys =
        PublicKeys::new(signing_public_key, encapsulation_public_key);
    (private_keys, public_keys)
}

/// Generates a key pair with specified schemes using a custom random number
/// generator.
///
/// This function provides the most control over key pair generation by allowing
/// custom specification of both cryptographic schemes and the random number
/// generator.
///
/// # Parameters
///
/// * `signature_scheme` - The signature scheme to use
/// * `encapsulation_scheme` - The key encapsulation scheme to use
/// * `rng` - A mutable reference to a random number generator
///
/// # Returns
///
/// A Result containing a tuple with `PrivateKeys` and `PublicKeys` if
/// successful, or an error if key generation fails.
///
/// # Errors
///
/// Returns an error if either the signature or encapsulation key generation
/// fails.
///
/// # Example
///
/// ```
/// use bc_components::{
///     EncapsulationScheme, SignatureScheme, keypair_opt_using,
/// };
/// use bc_rand::SecureRandomNumberGenerator;
///
/// // Create a random number generator
/// let mut rng = SecureRandomNumberGenerator;
///
/// // Generate a specific key pair deterministically
/// let result = keypair_opt_using(
///     SignatureScheme::Ecdsa,
///     EncapsulationScheme::X25519,
///     &mut rng,
/// );
/// assert!(result.is_ok());
/// ```
pub fn keypair_opt_using(
    signature_scheme: SignatureScheme,
    encapsulation_scheme: EncapsulationScheme,
    rng: &mut impl RandomNumberGenerator,
) -> Result<(PrivateKeys, PublicKeys)> {
    let (signing_private_key, signing_public_key) =
        signature_scheme.keypair_using(rng, "")?;
    let (encapsulation_private_key, encapsulation_public_key) =
        encapsulation_scheme.keypair_using(rng)?;
    let private_keys =
        PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
    let public_keys =
        PublicKeys::new(signing_public_key, encapsulation_public_key);
    Ok((private_keys, public_keys))
}
