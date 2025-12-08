//! SR25519 digital signature algorithm types.
//!
//! This module provides types for working with the SR25519 digital signature
//! algorithm:
//!
//! - `Sr25519PrivateKey`: A 32-byte private key for signing data
//! - `Sr25519PublicKey`: A 32-byte public key for verifying signatures
//!
//! SR25519 (Schnorr-Ristretto) is a signature scheme based on Schnorr signatures
//! over the Ristretto group. It provides:
//!
//! - High security and performance
//! - Non-deterministic signatures
//! - Compatibility with Substrate and Polkadot ecosystems
//! - Support for hierarchical deterministic key derivation (HDKD)
//!
//! Unlike Ed25519, SR25519 uses Schnorr signatures which enable more advanced
//! cryptographic protocols and better batching capabilities.

mod sr25519_private_key;
pub use sr25519_private_key::Sr25519PrivateKey;

mod sr25519_public_key;
pub use sr25519_public_key::{Sr25519PublicKey, SR25519_SIGNATURE_SIZE};
