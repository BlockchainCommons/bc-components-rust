//! Elliptic curve cryptography key types and operations.
//!
//! This module provides types and operations for elliptic curve cryptography (ECC),
//! specifically focusing on the secp256k1 curve used in Bitcoin and other cryptocurrencies.
//! It supports both traditional ECDSA (Elliptic Curve Digital Signature Algorithm) and
//! the newer Schnorr signature scheme (BIP-340).
//!
//! The main components are:
//!
//! - `ECPrivateKey`: A 32-byte private key for signing
//! - `ECPublicKey`: A 33-byte compressed public key for verification
//! - `ECUncompressedPublicKey`: A 65-byte uncompressed public key (legacy format)
//! - `SchnorrPublicKey`: A 32-byte x-only public key for BIP-340 Schnorr signatures
//!
//! All these types implement the `ECKeyBase` trait, which provides common functionality
//! for elliptic curve keys. The `ECKey` trait extends `ECKeyBase` to provide functionality
//! for deriving public keys from private keys. The `ECPublicKeyBase` trait provides
//! functionality for working with uncompressed public keys.
//!
//! ## Signature Schemes
//!
//! This module supports two signature schemes:
//!
//! - **ECDSA**: The traditional signature scheme used in Bitcoin and other cryptocurrencies
//! - **Schnorr**: A newer signature scheme (BIP-340) with advantages like linearity, 
//!   non-malleability, and smaller signature size

mod ec_key_base;
pub use ec_key_base::{ECKeyBase, ECKey};

mod ec_public_key_base;
pub use ec_public_key_base::ECPublicKeyBase;

mod ec_private_key;
pub use ec_private_key::{ECPrivateKey, ECDSA_PRIVATE_KEY_SIZE};

mod ec_public_key;
pub use ec_public_key::{ECPublicKey, ECDSA_PUBLIC_KEY_SIZE};

mod ec_uncompressed_public_key;
pub use ec_uncompressed_public_key::{ECUncompressedPublicKey, ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE};

mod schnorr_public_key;
pub use schnorr_public_key::{SchnorrPublicKey, SCHNORR_PUBLIC_KEY_SIZE};
