use bc_ur::prelude::*;

use crate::{
    Digest, EncapsulationPublicKey, Encrypter, Reference, ReferenceProvider,
    Signature, SigningPublicKey, Verifier, tags,
};

/// A container for an entity's public cryptographic keys.
///
/// `PublicKeys` combines a verification key for checking digital signatures
/// with an encapsulation key for encrypting messages, providing a complete
/// public key package for secure communication with an entity.
///
/// This type is designed to be freely shared across networks and systems,
/// allowing others to securely communicate with the key owner, who holds the
/// corresponding `PrivateKeys` instance.
///
/// # Components
///
/// * `signing_public_key` - A public key used for verifying digital signatures.
///   Can verify signatures created by the corresponding private key, which may
///   be Schnorr, ECDSA, Ed25519, or SSH-based.
///
/// * `encapsulation_public_key` - A public key used for encrypting messages
///   that can only be decrypted by the holder of the corresponding private key.
///   Can be X25519 or ML-KEM based.
///
/// # Use Cases
///
/// * Verifying the authenticity of signed messages or content
/// * Encrypting data for secure transmission to the key owner
/// * Identity verification in distributed systems
/// * Establishing secure communication channels
///
/// # Examples
///
/// ```
/// use bc_components::{EncapsulationPublicKey, keypair};
///
/// // Generate a key pair
/// let (private_keys, public_keys) = keypair();
///
/// // Get the encapsulation public key
/// let enc_pub_key = public_keys.enapsulation_public_key();
///
/// // The public key can be used for key encapsulation
/// // The resulting shared secret is only accessible to the
/// // holder of the corresponding private key
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PublicKeys {
    signing_public_key: SigningPublicKey,
    encapsulation_public_key: EncapsulationPublicKey,
}

impl PublicKeys {
    /// Restores a `PublicKeys` from a `SigningPublicKey` and an
    /// `EncapsulationPublicKey`.
    pub fn new(
        signing_public_key: SigningPublicKey,
        encapsulation_public_key: EncapsulationPublicKey,
    ) -> Self {
        Self { signing_public_key, encapsulation_public_key }
    }

    /// Returns the `SigningPublicKey` of this `PublicKeys`.
    pub fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public_key
    }

    /// Returns the `EncapsulationPublicKey` of this `PublicKeys`.
    pub fn enapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public_key
    }
}

/// A trait for types that can provide a complete set of public cryptographic
/// keys.
///
/// Types implementing this trait can be used as a source of `PublicKeys`,
/// which contain both verification and encryption public keys. This trait is
/// particularly useful for key management systems, wallets, identity systems,
/// or any component that needs to provide public keys for cryptographic
/// operations.
///
/// # Examples
///
/// ```ignore
/// # // Requires secp256k1 feature (enabled by default)
/// use bc_components::{PrivateKeyBase, PublicKeysProvider};
///
/// // Create a provider of public keys (in this case, a private key base
/// // that can derive the corresponding public keys)
/// let key_base = PrivateKeyBase::new();
///
/// // Get the public keys from the provider
/// let public_keys = key_base.public_keys();
///
/// // These public keys can be shared with others for secure communication
/// ```
pub trait PublicKeysProvider {
    /// Returns a complete set of public keys for cryptographic operations.
    ///
    /// The returned `PublicKeys` instance contains both verification and
    /// encryption public keys that can be used by other parties to securely
    /// communicate with the key owner.
    ///
    /// # Returns
    ///
    /// A `PublicKeys` instance containing the complete set of public keys.
    fn public_keys(&self) -> PublicKeys;
}

impl PublicKeysProvider for PublicKeys {
    fn public_keys(&self) -> PublicKeys { self.clone() }
}

impl ReferenceProvider for PublicKeys {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl AsRef<PublicKeys> for PublicKeys {
    fn as_ref(&self) -> &PublicKeys { self }
}

impl AsRef<SigningPublicKey> for PublicKeys {
    fn as_ref(&self) -> &SigningPublicKey { &self.signing_public_key }
}

impl AsRef<EncapsulationPublicKey> for PublicKeys {
    fn as_ref(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public_key
    }
}

impl CBORTagged for PublicKeys {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_PUBLIC_KEYS]) }
}

impl From<PublicKeys> for CBOR {
    fn from(value: PublicKeys) -> Self { value.tagged_cbor() }
}

impl CBORTaggedEncodable for PublicKeys {
    fn untagged_cbor(&self) -> CBOR {
        #[cfg(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "ssh",
            feature = "pqcrypto"
        ))]
        {
            let _signing_key_cbor: CBOR =
                self.signing_public_key.clone().into();
            let _encapsulation_key_cbor: CBOR =
                self.encapsulation_public_key.clone().into();
            vec![_signing_key_cbor, _encapsulation_key_cbor].into()
        }
        #[cfg(not(any(
            feature = "secp256k1",
            feature = "ed25519",
            feature = "ssh",
            feature = "pqcrypto"
        )))]
        {
            match self.signing_public_key {}
        }
    }
}

impl TryFrom<CBOR> for PublicKeys {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PublicKeys {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    return Err("PublicKeys must have two elements".into());
                }

                let signing_public_key =
                    SigningPublicKey::try_from(elements[0].clone())?;
                let encapsulation_public_key =
                    EncapsulationPublicKey::try_from(elements[1].clone())?;
                Ok(Self::new(signing_public_key, encapsulation_public_key))
            }
            _ => Err("PublicKeys must be an array".into()),
        }
    }
}

impl Verifier for PublicKeys {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        self.signing_public_key.verify(signature, message)
    }
}

impl Encrypter for PublicKeys {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        self.encapsulation_public_key.clone()
    }
}

impl std::fmt::Display for PublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PublicKeys({}, {}, {})",
            self.reference().ref_hex_short(),
            self.signing_public_key,
            self.encapsulation_public_key
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
        PrivateKeyBase, PublicKeys, PublicKeysProvider, ReferenceProvider,
    };

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_private_key_base() {
        crate::register_tags();
        let private_key_base = PrivateKeyBase::from_data(SEED);
        let public_keys = private_key_base.public_keys();

        let cbor = CBOR::from(public_keys.clone());

        let public_keys_2 = PublicKeys::try_from(cbor.clone()).unwrap();
        assert_eq!(public_keys, public_keys_2);

        let cbor_2 = CBOR::from(public_keys_2);
        assert_eq!(cbor, cbor_2);

        let ur = public_keys.ur_string();
        assert_eq!(
            ur,
            "ur:crypto-pubkeys/lftanshfhdcxzcgtcpytvsgafsondpjkbkoxaopsnniycawpnbnlwsgtregdfhgynyjksrgafmcstansgrhdcxlnfnwfzstovlrdfeuoghvwwyuesbcltsmetbgeurpfoyswfrzojlwdenjzckvadnrndtgsya"
        );
        assert_eq!(PublicKeys::from_ur_string(&ur).unwrap(), public_keys);

        assert_eq!(
            format!("{}", public_keys),
            "PublicKeys(c9ede672, SigningPublicKey(7efa2ea1, SchnorrPublicKey(b4df96ce)), EncapsulationPublicKey(bacae62f, X25519PublicKey(bacae62f)))"
        );
        assert_eq!(
            format!("{}", public_keys.reference()),
            "Reference(c9ede672)"
        );
    }
}
