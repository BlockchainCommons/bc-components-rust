use anyhow::{ bail, Error, Result };
use bc_ur::prelude::*;
use crate::{
    tags,
    Digest,
    EncapsulationPublicKey,
    Encrypter,
    Reference,
    ReferenceProvider,
    Signature,
    SigningPublicKey,
    Verifier,
};

/// Holds information used to communicate cryptographically with a remote entity.
///
/// Includes the entity's public signing key for verifying signatures, and
/// the entity's public encapsulation key used for public key encryption.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PublicKeys {
    signing_public_key: SigningPublicKey,
    encapsulation_public_key: EncapsulationPublicKey,
}

impl PublicKeys {
    /// Restores a `PublicKeys` from a `SigningPublicKey` and an `EncapsulationPublicKey`.
    pub fn new(
        signing_public_key: SigningPublicKey,
        encapsulation_public_key: EncapsulationPublicKey
    ) -> Self {
        Self {
            signing_public_key,
            encapsulation_public_key,
        }
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

pub trait PublicKeysProvider {
    fn public_keys(&self) -> PublicKeys;
}

impl PublicKeysProvider for PublicKeys {
    fn public_keys(&self) -> PublicKeys {
        self.clone()
    }
}

impl Verifier for PublicKeys {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        self.signing_public_key.verify(signature, message)
    }
}

impl ReferenceProvider for PublicKeys {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(self.tagged_cbor().to_cbor_data()))
    }
}

impl AsRef<PublicKeys> for PublicKeys {
    fn as_ref(&self) -> &PublicKeys {
        self
    }
}

impl AsRef<SigningPublicKey> for PublicKeys {
    fn as_ref(&self) -> &SigningPublicKey {
        &self.signing_public_key
    }
}

impl AsRef<EncapsulationPublicKey> for PublicKeys {
    fn as_ref(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public_key
    }
}

impl CBORTagged for PublicKeys {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_PUBLIC_KEYS])
    }
}

impl From<PublicKeys> for CBOR {
    fn from(value: PublicKeys) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for PublicKeys {
    fn untagged_cbor(&self) -> CBOR {
        let signing_key_cbor: CBOR = self.signing_public_key.clone().into();
        let encapsulation_key_cbor: CBOR = self.encapsulation_public_key.clone().into();
        vec![signing_key_cbor, encapsulation_key_cbor].into()
    }
}

impl TryFrom<CBOR> for PublicKeys {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PublicKeys {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("PublicKeys must have two elements");
                }

                let signing_public_key = SigningPublicKey::try_from(elements[0].clone())?;
                let encapsulation_public_key = EncapsulationPublicKey::try_from(
                    elements[1].clone()
                )?;
                Ok(Self::new(signing_public_key, encapsulation_public_key))
            }
            _ => bail!("PublicKeys must be an array"),
        }
    }
}

impl Encrypter for PublicKeys {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        self.encapsulation_public_key.clone()
    }
}

impl std::fmt::Display for PublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKeys({})", self.reference().ref_hex_short())
    }
}

#[cfg(test)]
mod tests {
    use bc_ur::{ UREncodable, URDecodable };
    use hex_literal::hex;
    use dcbor::prelude::*;

    use crate::{ PrivateKeyBase, PublicKeys, PublicKeysProvider, ReferenceProvider };

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
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

        assert_eq!(format!("{}", public_keys), "PublicKeys(c9ede672)");
        assert_eq!(format!("{}", public_keys.reference()), "Reference(c9ede672)");
    }
}
