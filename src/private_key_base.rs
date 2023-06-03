use std::rc::Rc;

use bc_crypto::RandomNumberGenerator;
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, Bytes};

use crate::{PrivateKeysDataProvider, SigningPrivateKey, AgreementPrivateKey, PublicKeyBase, tags_registry};

/// Holds unique data from which keys for signing and encryption can be derived.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKeyBase(Vec<u8>);

impl PrivateKeyBase {
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_data(data: &[u8]) -> Self {
        Self::from_vec(data.to_vec())
    }

    pub fn from_data_ref<T>(data: &T) -> Self where T: AsRef<[u8]> {
        Self::from_data(data.as_ref())
    }

    pub fn new() -> Self {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self::from_vec(rng.random_data(32))
    }

    pub fn new_with_provider<T: PrivateKeysDataProvider>(provider: &T) -> Self {
        Self::from_vec(provider.private_keys_data())
    }

    pub fn signing_private_key(&self) -> SigningPrivateKey {
        SigningPrivateKey::derive_from_key_material(&self.0)
    }

    pub fn agreement_private_key(&self) -> AgreementPrivateKey {
        AgreementPrivateKey::derive_from_key_material(&self.0)
    }

    pub fn public_keys(&self) -> PublicKeyBase {
        PublicKeyBase::new(self.signing_private_key().schnorr_public_key(), self.agreement_private_key().public_key())
    }

    pub fn ecdsa_public_keys(&self) -> PublicKeyBase {
        PublicKeyBase::new(self.signing_private_key().ecdsa_public_key(), self.agreement_private_key().public_key())
    }

    pub fn data(&self) -> &[u8] {
        self.into()
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

impl CBORTagged for PrivateKeyBase {
    const CBOR_TAG: Tag = tags_registry::PRIVATE_KEYBASE;
}

impl CBOREncodable for PrivateKeyBase {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for PrivateKeyBase {
    fn untagged_cbor(&self) -> CBOR {
        Bytes::from_data(&self.0).cbor()
    }
}

impl UREncodable for PrivateKeyBase { }

impl CBORDecodable for PrivateKeyBase {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PrivateKeyBase {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Rc<Self>, dcbor::Error> {
        let bytes = Bytes::from_cbor(untagged_cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(data);
        Ok(Rc::new(instance))
    }
}

impl URDecodable for PrivateKeyBase { }

impl URCodable for PrivateKeyBase { }
