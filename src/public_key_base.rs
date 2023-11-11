use bc_ur::prelude::*;
use crate::{SigningPublicKey, AgreementPublicKey, tags};
use anyhow::bail;

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
    pub fn new(signing_public_key: SigningPublicKey, agreement_public_key: AgreementPublicKey) -> Self {
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
    const CBOR_TAG: Tag = tags::PUBLIC_KEYBASE;
}

impl CBOREncodable for PublicKeyBase {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl From<PublicKeyBase> for CBOR {
    fn from(value: PublicKeyBase) -> Self {
        value.cbor()
    }
}

impl CBORTaggedEncodable for PublicKeyBase {
    fn untagged_cbor(&self) -> CBOR {
        vec![
            self.signing_public_key.cbor(),
            self.agreement_public_key.cbor(),
        ].cbor()
    }
}

impl UREncodable for PublicKeyBase { }

impl CBORDecodable for PublicKeyBase {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl TryFrom<CBOR> for PublicKeyBase {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(&cbor)
    }
}

impl TryFrom<&CBOR> for PublicKeyBase {
    type Error = anyhow::Error;

    fn try_from(cbor: &CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PublicKeyBase {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> anyhow::Result<Self> {
        match untagged_cbor {
            CBOR::Array(elements) => {
                if elements.len() != 2 {
                    bail!("PublicKeyBase must have two elements");
                }

                let signing_public_key = SigningPublicKey::from_cbor(&elements[0])?;
                let agreement_public_key = AgreementPublicKey::from_cbor(&elements[1])?;
                Ok(Self::new(signing_public_key, agreement_public_key))
            },
            _ => bail!("PublicKeyBase must be an array"),
        }
    }
}

impl URDecodable for PublicKeyBase { }

impl URCodable for PublicKeyBase { }

#[cfg(test)]
mod tests {
    use bc_ur::{UREncodable, URDecodable};
    use bytes::Bytes;
    use dcbor::{CBOREncodable, CBORDecodable};
    use hex_literal::hex;

    use crate::{PrivateKeyBase, PublicKeyBase};

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    fn test_private_key_base() {
        let private_key_base = PrivateKeyBase::from_data(Bytes::from_static(&SEED));
        let public_key_base = private_key_base.public_keys();

        let cbor = public_key_base.cbor();

        let public_key_base_2 = PublicKeyBase::from_cbor(&cbor).unwrap();
        assert_eq!(public_key_base, public_key_base_2);

        let cbor_2 = public_key_base_2.cbor();
        assert_eq!(cbor, cbor_2);

        let ur = public_key_base.ur_string();
        assert_eq!(ur, "ur:crypto-pubkeys/lftanshfhdcxzcgtcpytvsgafsondpjkbkoxaopsnniycawpnbnlwsgtregdfhgynyjksrgafmcstansgrhdcxlnfnwfzstovlrdfeuoghvwwyuesbcltsmetbgeurpfoyswfrzojlwdenjzckvadnrndtgsya");
        assert_eq!(PublicKeyBase::from_ur_string(&ur).unwrap(), public_key_base);
    }
}
