use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use schnorrkel::{
    Keypair, MiniSecretKey, SecretKey, Signature as SchnorrkelSignature,
    signing_context,
};

use crate::{
    Digest, Error, Reference, ReferenceProvider, Result, Sr25519PublicKey,
};

pub const SR25519_PRIVATE_KEY_SIZE: usize = 32;
pub const SR25519_SIGNATURE_SIZE: usize = 64;

/// An SR25519 private key for creating digital signatures.
///
/// SR25519 is a Schnorr signature scheme based on the Ristretto group, providing:
///
/// - Fast signature creation and verification
/// - Batch verification capabilities
/// - Hierarchical deterministic key derivation
/// - High security level (equivalent to 128 bits of symmetric security)
/// - Compatibility with Substrate and Polkadot ecosystems
///
/// This implementation allows:
/// - Creating random SR25519 private keys
/// - Deriving the corresponding public key
/// - Signing messages with context support
/// - Converting between various formats
#[derive(Clone, PartialEq, Eq)]
pub struct Sr25519PrivateKey {
    secret: SecretKey,
}

impl Sr25519PrivateKey {
    /// Creates a new random SR25519 private key.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Creates a new random SR25519 private key using the given random number
    /// generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        let mut seed = [0u8; SR25519_PRIVATE_KEY_SIZE];
        rng.fill_random_data(&mut seed);
        Self::from_seed(seed)
    }

    /// Creates an SR25519 private key from a 32-byte seed.
    pub fn from_seed(seed: [u8; SR25519_PRIVATE_KEY_SIZE]) -> Self {
        let mini_secret = MiniSecretKey::from_bytes(&seed)
            .expect("32 bytes always valid for MiniSecretKey");
        let secret = mini_secret.expand(schnorrkel::ExpansionMode::Ed25519);
        Self { secret }
    }

    /// Restores an SR25519 private key from a seed reference.
    pub fn from_seed_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != SR25519_PRIVATE_KEY_SIZE {
            return Err(Error::invalid_size(
                "SR25519 private key seed",
                SR25519_PRIVATE_KEY_SIZE,
                data.len(),
            ));
        }
        let mut seed = [0u8; SR25519_PRIVATE_KEY_SIZE];
        seed.copy_from_slice(data);
        Ok(Self::from_seed(seed))
    }

    /// Derives a new SR25519 private key from the given key material.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        let mut seed = [0u8; SR25519_PRIVATE_KEY_SIZE];
        let material = key_material.as_ref();

        // Use BLAKE2b to derive a seed from arbitrary length key material
        use blake2::{Blake2b512, Digest as Blake2Digest};
        let mut hasher = Blake2b512::new();
        hasher.update(material);
        let result = hasher.finalize();
        seed.copy_from_slice(&result[..32]);

        Self::from_seed(seed)
    }

    /// Returns the seed bytes of this private key.
    pub fn to_seed(&self) -> [u8; SR25519_PRIVATE_KEY_SIZE] {
        self.secret.to_bytes()[..SR25519_PRIVATE_KEY_SIZE]
            .try_into()
            .expect("secret key is 32 bytes")
    }

    /// Get the SR25519 private key seed as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.to_seed().to_vec()
    }

    /// Returns the private key seed as a hex string.
    pub fn hex(&self) -> String {
        hex::encode(self.to_seed())
    }

    /// Creates an SR25519 private key from a hex string.
    pub fn from_hex(hex_str: impl AsRef<str>) -> Result<Self> {
        let data = hex::decode(hex_str.as_ref())?;
        Self::from_seed_ref(data)
    }

    /// Derives the public key from this SR25519 private key.
    pub fn public_key(&self) -> Sr25519PublicKey {
        let keypair = Keypair {
            secret: self.secret.clone(),
            public: self.secret.to_public(),
        };
        Sr25519PublicKey::from_public_key(keypair.public)
    }

    /// Signs a message with this SR25519 private key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `context` - Optional signing context (defaults to "substrate" if None)
    pub fn sign(&self, message: impl AsRef<[u8]>) -> [u8; SR25519_SIGNATURE_SIZE] {
        self.sign_with_context(message, b"substrate")
    }

    /// Signs a message with a specific context.
    pub fn sign_with_context(
        &self,
        message: impl AsRef<[u8]>,
        context: &[u8],
    ) -> [u8; SR25519_SIGNATURE_SIZE] {
        let keypair = Keypair {
            secret: self.secret.clone(),
            public: self.secret.to_public(),
        };
        let ctx = signing_context(context);
        let signature: SchnorrkelSignature = keypair.sign(ctx.bytes(message.as_ref()));
        signature.to_bytes()
    }
}

impl From<[u8; SR25519_PRIVATE_KEY_SIZE]> for Sr25519PrivateKey {
    fn from(seed: [u8; SR25519_PRIVATE_KEY_SIZE]) -> Self {
        Self::from_seed(seed)
    }
}

// Note: AsRef<[u8]> is not implemented because we cannot return a reference
// to temporary data. Use to_seed() instead.

impl std::fmt::Debug for Sr25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sr25519PrivateKey({})", self.hex())
    }
}

impl Default for Sr25519PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceProvider for Sr25519PrivateKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(self.to_seed()))
    }
}

impl std::fmt::Display for Sr25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sr25519PrivateKey")
    }
}

impl std::hash::Hash for Sr25519PrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_seed().hash(state);
    }
}
