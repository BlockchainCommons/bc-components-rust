use crate::{ECKey, ECUncompressedPublicKey};

/// A type that can provide a single unique elliptic curve digital signature algorithm (ECDSA) uncompressed public key.
pub trait ECPublicKeyBase: ECKey {
    fn uncompressed_public_key(&self) -> ECUncompressedPublicKey;
}
