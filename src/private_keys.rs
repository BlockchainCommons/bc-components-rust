use anyhow::{ bail, Error, Result };
use bc_ur::prelude::*;
use crate::{
    tags,
    Decrypter,
    Digest,
    EncapsulationPrivateKey,
    Reference,
    ReferenceProvider,
    Signature,
    Signer,
    SigningPrivateKey,
};

/// Holds information used to communicate cryptographically with a remote
/// entity.
///
/// Includes the entity's private signing key for making signatures, and the
/// entity's private encapsulation key used to decrypt messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrivateKeys {
    signing_private_key: SigningPrivateKey,
    encapsulation_private_key: EncapsulationPrivateKey,
}

impl PrivateKeys {
    /// Restores a `PrivateKeys` from a `SigningPrivateKey` and an `EncapsulationPrivateKey`.
    pub fn with_keys(
        signing_private_key: SigningPrivateKey,
        encapsulation_private_key: EncapsulationPrivateKey
    ) -> Self {
        Self {
            signing_private_key,
            encapsulation_private_key,
        }
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

pub trait PrivateKeysProvider {
    fn private_keys(&self) -> PrivateKeys;
}

impl PrivateKeysProvider for PrivateKeys {
    fn private_keys(&self) -> PrivateKeys {
        self.clone()
    }
}

impl ReferenceProvider for PrivateKeys {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(self.tagged_cbor().to_cbor_data()))
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
        let signing_key_cbor: CBOR = self.signing_private_key.clone().into();
        let encapsulation_key_cbor: CBOR = self.encapsulation_private_key.clone().into();
        vec![signing_key_cbor, encapsulation_key_cbor].into()
    }
}

impl TryFrom<CBOR> for PrivateKeys {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PrivateKeys {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("PrivateKeys must have two elements");
                }

                let signing_private_key = SigningPrivateKey::try_from(elements[0].clone())?;
                let encapsulation_private_key = EncapsulationPrivateKey::try_from(
                    elements[1].clone()
                )?;
                Ok(Self::with_keys(signing_private_key, encapsulation_private_key))
            }
            _ => bail!("PrivateKeys must be an array"),
        }
    }
}

impl Signer for PrivateKeys {
    fn sign_with_options(
        &self,
        message: &dyn AsRef<[u8]>,
        options: Option<crate::SigningOptions>
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
        write!(f, "PrivateKeys({})", self.reference().ref_hex_short())
    }
}

#[cfg(test)]
mod tests {
    use bc_ur::{ UREncodable, URDecodable };
    use hex_literal::hex;
    use dcbor::prelude::*;

    use crate::{ PrivateKeyBase, PrivateKeys, PrivateKeysProvider, ReferenceProvider };

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
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

        assert_eq!(format!("{}", private_keys), "PrivateKeys(fa742ac8)");
        assert_eq!(format!("{}", private_keys.reference()), "Reference(fa742ac8)");
    }
}
