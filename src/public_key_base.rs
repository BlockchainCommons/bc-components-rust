use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable};

use crate::{SigningPublicKey, AgreementPublicKey, tags};

/// Holds information used to communicate cryptographically with a remote entity.
///
/// Includes the entity's public signing key for verifying signatures, and
/// the entity's public agreement key used for X25519 key agreement.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKeyBase {
    signing_public_key: SigningPublicKey,
    agreement_public_key: AgreementPublicKey,
}

impl PublicKeyBase {
    pub fn new(signing_public_key: SigningPublicKey, agreement_public_key: AgreementPublicKey) -> Self {
        Self {
            signing_public_key,
            agreement_public_key,
        }
    }

    pub fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public_key
    }

    pub fn agreement_public_key(&self) -> &AgreementPublicKey {
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
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PublicKeyBase {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        match untagged_cbor {
            CBOR::Array(elements) => {
                if elements.len() != 2 {
                    return Err(dcbor::Error::InvalidFormat);
                }

                let signing_public_key = SigningPublicKey::from_cbor(&elements[0])?;
                let agreement_public_key = AgreementPublicKey::from_cbor(&elements[1])?;
                Ok(Self::new(signing_public_key, agreement_public_key))
            },
            _ => Err(dcbor::Error::InvalidFormat),
        }
    }
}

impl URDecodable for PublicKeyBase { }

impl URCodable for PublicKeyBase { }
