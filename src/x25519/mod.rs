//! X25519 key agreement protocol types.
//!
//! This module provides types for working with the X25519 key agreement protocol:
//!
//! - `X25519PrivateKey`: A 32-byte private key for key agreement
//! - `X25519PublicKey`: A 32-byte public key for key agreement
//!
//! X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on Curve25519.
//! It allows two parties to establish a shared secret key over an insecure channel.
//! The protocol provides high security and performance, with 128-bit security level
//! and efficient implementations.
//!
//! Unlike the related Ed25519 algorithm which is used for digital signatures,
//! X25519 is specifically designed for key agreement and encryption.

mod x25519_private_key;
pub use x25519_private_key::X25519PrivateKey;

mod x25519_public_key;
pub use x25519_public_key::X25519PublicKey;
