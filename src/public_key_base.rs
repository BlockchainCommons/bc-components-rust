use bc_ur::prelude::*;
use crate::{ tags, AgreementPublicKey, Signature, SigningPublicKey, Verifier };
use anyhow::{ bail, Error, Result };

/// Holds information used to communicate cryptographically with a remote entity.
///
/// Includes the entity's public signing key for verifying signatures, and
/// the entity's public agreement key used for X25519 key agreement.
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub struct PublicKeyBase {
    signing_public_key: SigningPublicKey,
    agreement_public_key: AgreementPublicKey,
}

impl PublicKeyBase {
    /// Restores a `PublicKeyBase` from a `SigningPublicKey` and an `AgreementPublicKey`.
    pub fn new(
        signing_public_key: SigningPublicKey,
        agreement_public_key: AgreementPublicKey
    ) -> Self {
        Self {
            signing_public_key,
            agreement_public_key,
        }
    }

    /// Returns the `SigningPublicKey` of this `PublicKeyBase`.
    pub fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public_key
    }

    /// Returns the `AgreementPublicKey` of this `PublicKeyBase`.
    pub fn agreement_public_key(&self) -> &AgreementPublicKey {
        &self.agreement_public_key
    }
}

impl Verifier for PublicKeyBase {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        self.signing_public_key.verify(signature, message)
    }
}

impl AsRef<PublicKeyBase> for PublicKeyBase {
    fn as_ref(&self) -> &PublicKeyBase {
        self
    }
}

impl AsRef<SigningPublicKey> for PublicKeyBase {
    fn as_ref(&self) -> &SigningPublicKey {
        &self.signing_public_key
    }
}

impl AsRef<AgreementPublicKey> for PublicKeyBase {
    fn as_ref(&self) -> &AgreementPublicKey {
        &self.agreement_public_key
    }
}

impl CBORTagged for PublicKeyBase {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_PUBLIC_KEY_BASE])
    }
}

impl From<PublicKeyBase> for CBOR {
    fn from(value: PublicKeyBase) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for PublicKeyBase {
    fn untagged_cbor(&self) -> CBOR {
        let signing_key_cbor: CBOR = self.signing_public_key.clone().into();
        let agreement_key_cbor: CBOR = self.agreement_public_key.clone().into();
        vec![signing_key_cbor, agreement_key_cbor].into()
    }
}

impl TryFrom<CBOR> for PublicKeyBase {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PublicKeyBase {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        match untagged_cbor.as_case() {
            CBORCase::Array(elements) => {
                if elements.len() != 2 {
                    bail!("PublicKeyBase must have two elements");
                }

                let signing_public_key = SigningPublicKey::try_from(elements[0].clone())?;
                let agreement_public_key = AgreementPublicKey::try_from(elements[1].clone())?;
                Ok(Self::new(signing_public_key, agreement_public_key))
            }
            _ => bail!("PublicKeyBase must be an array"),
        }
    }
}

#[cfg(test)]
mod tests {
    use bc_ur::{ UREncodable, URDecodable };
    use hex_literal::hex;
    use dcbor::prelude::*;

    use crate::{ PrivateKeyBase, PublicKeyBase };

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    fn test_private_key_base() {
        crate::register_tags();
        let private_key_base = PrivateKeyBase::from_data(SEED);
        let public_key_base = private_key_base.schnorr_public_key_base();

        let cbor = CBOR::from(public_key_base.clone());

        let public_key_base_2 = PublicKeyBase::try_from(cbor.clone()).unwrap();
        assert_eq!(public_key_base, public_key_base_2);

        let cbor_2 = CBOR::from(public_key_base_2);
        assert_eq!(cbor, cbor_2);

        let ur = public_key_base.ur_string();
        assert_eq!(
            ur,
            "ur:crypto-pubkeys/lftanshfhdcxzcgtcpytvsgafsondpjkbkoxaopsnniycawpnbnlwsgtregdfhgynyjksrgafmcstansgrhdcxlnfnwfzstovlrdfeuoghvwwyuesbcltsmetbgeurpfoyswfrzojlwdenjzckvadnrndtgsya"
        );
        assert_eq!(PublicKeyBase::from_ur_string(&ur).unwrap(), public_key_base);
    }
}
