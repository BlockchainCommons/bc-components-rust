use bc_rand::{ rng_random_data, RandomNumberGenerator, SecureRandomNumberGenerator };
use bc_ur::prelude::*;
use anyhow::{ bail, Result };
use ssh_key::private::{
    DsaKeypair,
    EcdsaKeypair,
    Ed25519Keypair,
    KeypairData,
    PrivateKey as SSHPrivateKey,
    RsaKeypair,
};
use ssh_key::Algorithm as SSHAlgorithm;
use zeroize::ZeroizeOnDrop;

use crate::{
    tags, Decrypter, ECKey, ECPrivateKey, Ed25519PrivateKey, EncapsulationPrivateKey, EncapsulationPublicKey, HKDFRng, PrivateKeyDataProvider, PrivateKeys, PrivateKeysProvider, PublicKeys, PublicKeysProvider, Signature, Signer, SigningOptions, SigningPrivateKey, Verifier, X25519PrivateKey
};

/// A secure foundation for deriving multiple cryptographic keys.
///
/// `PrivateKeyBase` serves as a root of cryptographic material from which various
/// types of keys can be deterministically derived. It securely manages the underlying
/// key material and provides methods to derive specific cryptographic keys for different
/// purposes.
///
/// It supports:
/// - Deterministic derivation of signing keys (Schnorr, ECDSA, Ed25519)
/// - Deterministic derivation of encryption keys (X25519)
/// - SSH key generation for various algorithms (Ed25519, ECDSA, DSA, RSA)
/// - Key pair generation for both signing and encryption
///
/// This design allows a single master seed to generate multiple secure keys
/// for different cryptographic operations, similar to the concept of an
/// HD wallet in cryptocurrency systems.
///
/// # Security
///
/// `PrivateKeyBase` implements `ZeroizeOnDrop` to securely erase the sensitive key
/// material from memory when the object is dropped, reducing the risk of key
/// extraction via memory attacks.
///
/// # Examples
///
/// Creating and using a PrivateKeyBase:
///
/// ```
/// use bc_components::PrivateKeyBase;
/// use bc_components::Signer;
/// use bc_components::{PrivateKeysProvider, PublicKeysProvider};
///
/// // Create a new random PrivateKeyBase
/// let key_base = PrivateKeyBase::new();
///
/// // Sign a message using the derived Schnorr key
/// let message = b"Hello, world!";
/// let signature = key_base.sign(message).unwrap();
///
/// // Generate a key pair for public/private key operations
/// let (private_keys, public_keys) = (key_base.private_keys(), key_base.public_keys());
/// ```
#[derive(Clone, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PrivateKeyBase(Vec<u8>);

impl Signer for PrivateKeyBase {
    fn sign_with_options(
        &self,
        message: &dyn AsRef<[u8]>,
        options: Option<SigningOptions>
    ) -> Result<Signature> {
        let schnorr_key = self.schnorr_signing_private_key();
        schnorr_key.sign_with_options(message, options)
    }
}

impl Verifier for PrivateKeyBase {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        let schnorr_key = self.schnorr_signing_private_key().to_schnorr().unwrap().public_key();
        match signature.to_schnorr() {
            Some(schnorr_signature) => schnorr_key.verify(schnorr_signature, message),
            None => false,
        }
    }
}

impl Decrypter for PrivateKeyBase {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        EncapsulationPrivateKey::X25519(self.x25519_private_key())
    }
}

impl PrivateKeyBase {
    /// Generate a new random `PrivateKeyBase`.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Restores a `PrivateKeyBase` from bytes.
    pub fn from_data(data: impl Into<Vec<u8>>) -> Self {
        Self(data.into())
    }

    /// Restores a `PrivateKeyBase` from an optional reference to an array of bytes.
    ///
    /// If the data is `None`, a new random `PrivateKeyBase` is generated.
    pub fn from_optional_data(data: Option<impl Into<Vec<u8>>>) -> Self {
        match data {
            Some(data) => Self::from_data(data),
            None => Self::new(),
        }
    }

    /// Generate a new random `PrivateKeyBase` using the given random number generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self::from_data(rng_random_data(rng, 32))
    }

    /// Create a new `PrivateKeyBase` from the given private keys data provider.
    pub fn new_with_provider(provider: impl PrivateKeyDataProvider) -> Self {
        Self::from_data(provider.private_key_data())
    }

    /// Derive a new ECDSA `SigningPrivateKey` from this `PrivateKeyBase`.
    pub fn ecdsa_signing_private_key(&self) -> SigningPrivateKey {
        SigningPrivateKey::new_ecdsa(ECPrivateKey::derive_from_key_material(&self.0))
    }

    /// Derive a new Schnorr `SigningPrivateKey` from this `PrivateKeyBase`.
    pub fn schnorr_signing_private_key(&self) -> SigningPrivateKey {
        SigningPrivateKey::new_schnorr(ECPrivateKey::derive_from_key_material(&self.0))
    }

    /// Derive a new Ed25519 `SigningPrivateKey` from this `PrivateKeyBase`.
    pub fn ed25519_signing_private_key(&self) -> SigningPrivateKey {
        SigningPrivateKey::new_ed25519(Ed25519PrivateKey::derive_from_key_material(&self.0))
    }

    /// Derive a new SSH `SigningPrivateKey` from this `PrivateKeyBase`.
    pub fn ssh_signing_private_key(
        &self,
        algorithm: SSHAlgorithm,
        comment: impl Into<String>
    ) -> Result<SigningPrivateKey> {
        let mut rng = HKDFRng::new(&self.0, algorithm.as_str());
        let keypair = match algorithm {
            SSHAlgorithm::Dsa => { KeypairData::Dsa(DsaKeypair::random(&mut rng)?) }
            SSHAlgorithm::Ecdsa { curve } => {
                KeypairData::Ecdsa(EcdsaKeypair::random(&mut rng, curve)?)
            }
            SSHAlgorithm::Ed25519 => { KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)) }
            SSHAlgorithm::Rsa { hash: _ } => {
                KeypairData::Rsa(RsaKeypair::random(&mut rng, 2048)?)
            }
            _ => bail!("Unsupported SSH algorithm: {:?}", algorithm.as_str()),
        };
        let private_key = SSHPrivateKey::new(keypair, comment)?;
        Ok(SigningPrivateKey::new_ssh(private_key))
    }

    /// Derive a new `X25519PrivateKey` from this `PrivateKeyBase`.
    ///
    /// An X25519 key for public key encryption.
    pub fn x25519_private_key(&self) -> X25519PrivateKey {
        X25519PrivateKey::derive_from_key_material(&self.0)
    }

    /// Derive a new `PrivateKeys` from this `PrivateKeyBase`.
    ///
    /// - Includes a Schnorr private key for signing.
    /// - Includes an X25519 private key for encryption.
    pub fn schnorr_private_keys(&self) -> PrivateKeys {
        PrivateKeys::with_keys(
            self.schnorr_signing_private_key(),
            EncapsulationPrivateKey::X25519(self.x25519_private_key())
        )
    }

    /// Derive a new `PublicKeys` from this `PrivateKeyBase`.
    ///
    /// - Includes a Schnorr public key for signing.
    /// - Includes an X25519 public key encryption.
    pub fn schnorr_public_keys(&self) -> PublicKeys {
        PublicKeys::new(
            self.schnorr_signing_private_key().public_key().unwrap(),
            EncapsulationPublicKey::X25519(self.x25519_private_key().public_key())
        )
    }

    /// Derive a new `PrivateKeys` from this `PrivateKeyBase`.
    ///
    /// - Includes an ECDSA private key for signing.
    /// - Includes an X25519 private key for encryption.
    pub fn ecdsa_private_keys(&self) -> PrivateKeys {
        PrivateKeys::with_keys(
            self.ecdsa_signing_private_key(),
            EncapsulationPrivateKey::X25519(self.x25519_private_key())
        )
    }

    /// Derive a new `PublicKeys` from this `PrivateKeyBase`.
    ///
    /// - Includes an ECDSA public key for signing.
    /// - Includes an X25519 public key for encryption.
    pub fn ecdsa_public_keys(&self) -> PublicKeys {
        PublicKeys::new(
            self.ecdsa_signing_private_key().public_key().unwrap(),
            EncapsulationPublicKey::X25519(self.x25519_private_key().public_key())
        )
    }

    /// Derive a new `PrivateKeys` from this `PrivateKeyBase`.
    ///
    /// - Includes an SSH private key for signing.
    /// - Includes an X25519 private key for encryption.
    pub fn ssh_private_keys(
        &self,
        algorithm: SSHAlgorithm,
        comment: impl Into<String>
    ) -> Result<PrivateKeys> {
        let private_key = self.ssh_signing_private_key(algorithm, comment)?;
        Ok(
            PrivateKeys::with_keys(
                private_key,
                EncapsulationPrivateKey::X25519(self.x25519_private_key())
            )
        )
    }

    /// Derive a new `PublicKeys` from this `PrivateKeyBase`.
    ///
    /// - Includes an SSH public key for signing.
    /// - Includes an X25519 public key for encryption.
    pub fn ssh_public_keys(
        &self,
        algorithm: SSHAlgorithm,
        comment: impl Into<String>
    ) -> Result<PublicKeys> {
        let private_key = self.ssh_signing_private_key(algorithm, comment)?;
        Ok(
            PublicKeys::new(
                private_key.public_key().unwrap(),
                EncapsulationPublicKey::X25519(self.x25519_private_key().public_key())
            )
        )
    }

    /// Get the raw data of this `PrivateKeyBase`.
    pub fn data(&self) -> &[u8] {
        self.into()
    }
}

impl PrivateKeysProvider for PrivateKeyBase {
    fn private_keys(&self) -> PrivateKeys {
        PrivateKeys::with_keys(
            self.schnorr_signing_private_key(),
            EncapsulationPrivateKey::X25519(self.x25519_private_key())
        )
    }
}

impl PublicKeysProvider for PrivateKeyBase {
    fn public_keys(&self) -> PublicKeys {
        self.schnorr_public_keys()
    }
}

impl Default for PrivateKeyBase {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PrivateKeyBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKeyBase")
    }
}

impl<'a> From<&'a PrivateKeyBase> for &'a [u8] {
    fn from(value: &'a PrivateKeyBase) -> Self {
        &value.0
    }
}

impl AsRef<PrivateKeyBase> for PrivateKeyBase {
    fn as_ref(&self) -> &PrivateKeyBase {
        self
    }
}

impl AsRef<[u8]> for PrivateKeyBase {
    fn as_ref(&self) -> &[u8] {
        self.into()
    }
}

impl CBORTagged for PrivateKeyBase {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_PRIVATE_KEY_BASE])
    }
}

impl From<PrivateKeyBase> for CBOR {
    fn from(value: PrivateKeyBase) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for PrivateKeyBase {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(&self.0)
    }
}

impl TryFrom<CBOR> for PrivateKeyBase {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PrivateKeyBase {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        let instance = Self::from_data(data);
        Ok(instance)
    }
}

#[cfg(test)]
mod tests {
    use bc_ur::{ UREncodable, URDecodable };
    use hex_literal::hex;

    use crate::PrivateKeyBase;

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    fn test_private_key_base() {
        crate::register_tags();
        let private_key_base = PrivateKeyBase::from_data(SEED);
        assert_eq!(
            private_key_base.ecdsa_signing_private_key().to_ecdsa().unwrap().data(),
            &hex!("9505a44aaf385ce633cf0e2bc49e65cc88794213bdfbf8caf04150b9c4905f5a")
        );
        assert_eq!(
            private_key_base
                .schnorr_signing_private_key()
                .public_key()
                .unwrap()
                .to_schnorr()
                .unwrap()
                .data(),
            &hex!("fd4d22f9e8493da52d730aa402ac9e661deca099ef4db5503f519a73c3493e18")
        );
        assert_eq!(
            private_key_base.x25519_private_key().data(),
            &hex!("77ff838285a0403d3618aa8c30491f99f55221be0b944f50bfb371f43b897485")
        );
        assert_eq!(
            private_key_base.x25519_private_key().public_key().data(),
            &hex!("863cf3facee3ba45dc54e5eedecb21d791d64adfb0a1c63bfb6fea366c1ee62b")
        );

        let ur = private_key_base.ur_string();
        assert_eq!(ur, "ur:crypto-prvkey-base/gdhkwzdtfthptokigtvwnnjsqzcxknsktdsfecsbbk");
        assert_eq!(PrivateKeyBase::from_ur_string(&ur).unwrap(), private_key_base);
    }
}
