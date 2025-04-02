//! Ed25519 digital signature algorithm types.
//!
//! This module provides types for working with the Ed25519 digital signature algorithm:
//!
//! - `Ed25519PrivateKey`: A 32-byte private key for signing data
//! - `Ed25519PublicKey`: A 32-byte public key for verifying signatures
//!
//! Ed25519 is an elliptic curve digital signature algorithm that provides high security
//! and performance, with signatures that are deterministic and resilient against side-channel 
//! attacks. It's based on the Edwards curve over the finite field GF(2^255 - 19), hence the name.
//!
//! Unlike the similar X25519 key agreement scheme, Ed25519 is specifically designed for
//! digital signatures rather than key exchange.

mod ed25519_private_key;
pub use ed25519_private_key::Ed25519PrivateKey;

mod ed25519_public_key;
pub use ed25519_public_key::Ed25519PublicKey;
