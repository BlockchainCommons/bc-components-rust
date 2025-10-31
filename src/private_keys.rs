use bc_ur::prelude::*;

use crate::{
    Decrypter, Digest, EncapsulationPrivateKey, Reference, ReferenceProvider,
    Result, Signature, Signer, SigningPrivateKey, tags,
};

/// A container for an entity's private cryptographic keys.
///
/// `PrivateKeys` combines a signing key for creating digital signatures with an
/// encapsulation key for decrypting messages, providing a complete private key
/// package for cryptographic operations.
///
/// This type is typically used in conjunction with its public counterpart,
/// `PublicKeys`, to enable secure communication between entities. The private
/// keys remain with the owner, while the corresponding public keys can be
/// freely shared.
///
/// # Components
///
/// * `signing_private_key` - A private key used for creating digital
///   signatures. Can be Schnorr, ECDSA, Ed25519, or SSH-based, depending on the
///   security needs.
///
/// * `encapsulation_private_key` - A private key used for decrypting messages
///   that were encrypted using the corresponding public key. Can be X25519 or
///   ML-KEM based.
///
/// # Security
///
/// This struct contains highly sensitive cryptographic material and should be
/// handled with appropriate security measures:
///
/// - Minimize serialization and storage of private keys
/// - Ensure secure memory handling and proper zeroization
/// - Apply access controls and encryption when at rest
/// - Consider using hardware security modules for production systems
///
/// # Examples
///
/// ```
/// use bc_components::{Signer, Verifier, keypair};
///
/// // Generate a new key pair with default schemes
/// let (private_keys, public_keys) = keypair();
///
/// // Sign a message using the private keys
/// let message = b"Hello, world!";
/// let signature = private_keys.sign(message).unwrap();
///
/// // Verify the signature using the corresponding public keys
/// assert!(public_keys.verify(&signature, message));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrivateKeys {
    signing_private_key: SigningPrivateKey,
    encapsulation_private_key: EncapsulationPrivateKey,
}

impl PrivateKeys {
    /// Restores a `PrivateKeys` from a `SigningPrivateKey` and an
    /// `EncapsulationPrivateKey`.
    pub fn with_keys(
        signing_private_key: SigningPrivateKey,
        encapsulation_private_key: EncapsulationPrivateKey,
    ) -> Self {
        Self { signing_private_key, encapsulation_private_key }
    }

    /// Returns the `SigningPrivateKey` of this `PrivateKeys`.
    pub fn signing_private_key(&self) -> &SigningPrivateKey {
        &self.signing_private_key
    }

    /// Returns the `EncapsulationPrivateKey` of this `PrivateKeys`.
    pub fn enapsulation_private_key(&self) -> &EncapsulationPrivateKey {
        &self.encapsulation_private_key
    }
}

/// A trait for types that can provide a complete set of private cryptographic
/// keys.
///
/// Types implementing this trait can be used as a source of `PrivateKeys`,
/// which contain both signing and encryption private keys. This trait is
/// particularly useful for key management systems, wallets, or other components
/// that need to generate or access cryptographic key material.
///
/// # Examples
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{PrivateKeyBase, PrivateKeysProvider};
///
/// // Create a provider of private keys
/// let key_base = PrivateKeyBase::new();
///
/// // Get the private keys from the provider
/// let private_keys = key_base.private_keys();
/// ```
pub trait PrivateKeysProvider {
    /// Returns a complete set of private keys for cryptographic operations.
    ///
    /// The returned `PrivateKeys` instance contains both signing and encryption
    /// private keys that can be used for various cryptographic operations.
    ///
    /// # Returns
    ///
    /// A `PrivateKeys` instance containing the complete set of private keys.
    fn private_keys(&self) -> PrivateKeys;
}

impl PrivateKeysProvider for PrivateKeys {
    fn private_keys(&self) -> PrivateKeys {
        self.clone()
    }
}

impl ReferenceProvider for PrivateKeys {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl AsRef<PrivateKeys> for PrivateKeys {
    fn as_ref(&self) -> &PrivateKeys {
        self
    }
}

impl AsRef<SigningPrivateKey> for PrivateKeys {
    fn as_ref(&self) -> &SigningPrivateKey {
        &self.signing_private_key
    }
}

impl AsRef<EncapsulationPrivateKey> for PrivateKeys {
    fn as_ref(&self) -> &EncapsulationPrivateKey {
        &self.encapsulation_private_key
    }
}

impl CBORTagged for PrivateKeys {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_PRIVATE_KEYS])
    }
}

impl From<PrivateKeys> for CBOR {
    fn from(value: PrivateKeys) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for PrivateKeys {
    fn untagged_cbor(&self) -> CBOR {
        #[cfg(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "ssh",
            feature = "pqcrypto"
        ))]
        {
            let _signing_key_cbor: CBOR =
                self.signing_private_key.clone().into();
            let _encapsulation_key_cbor: CBOR =
                self.encapsulation_private_key.clone().into();
            vec![_signing_key_cbor, _encapsulation_key_cbor].into()
        }
        #[cfg(not(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "ssh",
            feature = "pqcrypto"
        )))]
        {
            match self.signing_private_key {}
        }
    }
}

impl TryFrom<CBOR> for PrivateKeys {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PrivateKeys {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("PrivateKeys must have two elements".into());
                }

                let signing_private_key =
                    SigningPrivateKey::try_from(elements[0].clone())?;
                let encapsulation_private_key =
                    EncapsulationPrivateKey::try_from(elements[1].clone())?;
                Ok(Self::with_keys(
                    signing_private_key,
                    encapsulation_private_key,
                ))
            }
            _ => Err("PrivateKeys must be an array".into()),
        }
    }
}

impl Signer for PrivateKeys {
    fn sign_with_options(
        &self,
        message: &dyn AsRef<[u8]>,
        options: Option<crate::SigningOptions>,
    ) -> Result<Signature> {
        self.signing_private_key.sign_with_options(message, options)
    }
}

impl Decrypter for PrivateKeys {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.encapsulation_private_key.clone()
    }
}

impl std::fmt::Display for PrivateKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrivateKeys({}, {}, {})",
            self.reference().ref_hex_short(),
            self.signing_private_key,
            self.encapsulation_private_key
        )
    }
}

#[cfg(test)]
#[cfg(feature = "secp256k1")]
mod tests {
    use bc_ur::{URDecodable, UREncodable};
    use dcbor::prelude::*;
    use hex_literal::hex;

    use crate::{
        PrivateKeyBase, PrivateKeys, PrivateKeysProvider, ReferenceProvider,
    };

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_private_keys() {
        crate::register_tags();

        let private_key_base = PrivateKeyBase::from_data(SEED);
        let private_keys = private_key_base.private_keys();

        let cbor = CBOR::from(private_keys.clone());
        println!("{}", cbor.diagnostic_annotated());

        let private_keys_2 = PrivateKeys::try_from(cbor.clone()).unwrap();
        assert_eq!(private_keys, private_keys_2);

        let cbor_2 = CBOR::from(private_keys_2);
        assert_eq!(cbor, cbor_2);

        let ur = private_keys.ur_string();
        assert_eq!(
            ur,
            "ur:crypto-prvkeys/lftansgohdcxmdahoxgepeethhvaeotkbadnssnnihsflokkfwbwryzoyasgwtfpgdrhssmhhehttansgehdcxktzmlslflpnbfzfsencspklkdygactnlykgmclrnbdmwgwgdrsqdjswkfrldjylpmtdpskfx"
        );
        assert_eq!(PrivateKeys::from_ur_string(&ur).unwrap(), private_keys);

        assert_eq!(
            format!("{}", private_keys),
            "PrivateKeys(fa742ac8, SigningPrivateKey(2a645922, ECPrivateKey(0b02c820)), EncapsulationPrivateKey(ded5f016, X25519PrivateKey(ded5f016)))"
        );
        assert_eq!(
            format!("{}", private_keys.reference()),
            "Reference(fa742ac8)"
        );
    }
}
