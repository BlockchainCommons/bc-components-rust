use schnorrkel::{
    PublicKey, Signature as SchnorrkelSignature, signing_context,
};

use crate::{Digest, Error, Reference, ReferenceProvider, Result};

pub const SR25519_PUBLIC_KEY_SIZE: usize = 32;
pub const SR25519_SIGNATURE_SIZE: usize = 64;

/// An SR25519 public key for verifying digital signatures.
///
/// SR25519 public keys are used to verify signatures created with the
/// corresponding private key. The SR25519 signature system provides:
///
/// - Fast signature verification
/// - Batch verification capabilities
/// - Small public keys (32 bytes)
/// - High security with resistance to various attacks
/// - Compatibility with Substrate and Polkadot ecosystems
///
/// This implementation allows:
/// - Creating SR25519 public keys from raw data
/// - Verifying signatures against messages
/// - Converting between various formats
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sr25519PublicKey([u8; SR25519_PUBLIC_KEY_SIZE]);

impl Sr25519PublicKey {
    /// Restores an SR25519 public key from an array of bytes.
    pub const fn from_data(data: [u8; SR25519_PUBLIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restores an SR25519 public key from a byte reference.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != SR25519_PUBLIC_KEY_SIZE {
            return Err(Error::invalid_size(
                "SR25519 public key",
                SR25519_PUBLIC_KEY_SIZE,
                data.len(),
            ));
        }
        let mut key = [0u8; SR25519_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    /// Creates an SR25519PublicKey from a schnorrkel PublicKey.
    pub(crate) fn from_public_key(public: PublicKey) -> Self {
        Self(public.to_bytes())
    }

    /// Returns the SR25519 public key as an array of bytes.
    pub fn data(&self) -> &[u8; SR25519_PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Get the SR25519 public key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /// Returns the public key as a hex string.
    fn hex(&self) -> String {
        hex::encode(self.data())
    }

    /// Creates an SR25519 public key from a hex string.
    pub fn from_hex(hex_str: impl AsRef<str>) -> Result<Self> {
        let data = hex::decode(hex_str.as_ref())?;
        Self::from_data_ref(data)
    }

    /// Converts this public key to a schnorrkel PublicKey.
    fn to_schnorrkel_public(self) -> Result<PublicKey> {
        PublicKey::from_bytes(&self.0).map_err(|e| {
            Error::general(format!("Invalid SR25519 public key: {}", e))
        })
    }

    /// Verifies the given SR25519 signature for the given message using this
    /// SR25519 public key with the default "substrate" context.
    pub fn verify(
        &self,
        signature: &[u8; SR25519_SIGNATURE_SIZE],
        message: impl AsRef<[u8]>,
    ) -> bool {
        self.verify_with_context(signature, message, b"substrate")
    }

    /// Verifies a signature with a specific context.
    pub fn verify_with_context(
        &self,
        signature: &[u8; SR25519_SIGNATURE_SIZE],
        message: impl AsRef<[u8]>,
        context: &[u8],
    ) -> bool {
        let public_key = match self.to_schnorrkel_public() {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match SchnorrkelSignature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let ctx = signing_context(context);
        public_key
            .verify(ctx.bytes(message.as_ref()), &sig)
            .is_ok()
    }
}

impl AsRef<[u8]> for Sr25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Sr25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sr25519PublicKey({})", self.hex())
    }
}

impl From<[u8; SR25519_PUBLIC_KEY_SIZE]> for Sr25519PublicKey {
    fn from(value: [u8; SR25519_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl ReferenceProvider for Sr25519PublicKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(self.data()))
    }
}

impl std::fmt::Display for Sr25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sr25519PublicKey({})", self.ref_hex_short())
    }
}
