use bc_crypto::RandomNumberGenerator;
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, bstring, into_bstring};

use crate::{PrivateKeysDataProvider, SigningPrivateKey, AgreementPrivateKey, PublicKeyBase, tags_registry};

/// Holds unique data from which keys for signing and encryption can be derived.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKeyBase(Vec<u8>);

impl PrivateKeyBase {
    pub const fn from_vec(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_data(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn from_data_ref<T>(data: &T) -> Self where T: AsRef<[u8]> {
        Self(data.as_ref().to_vec())
    }

    pub fn new() -> Self {
        let mut rng = bc_crypto::SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    pub fn from_optional_data<D>(data: Option<D>) -> Self where D: AsRef<[u8]> {
        match data {
            Some(data) => Self::from_data_ref(&data),
            None => Self::new(),
        }
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
        bstring(&self.0)
    }
}

impl UREncodable for PrivateKeyBase { }

impl CBORDecodable for PrivateKeyBase {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_untagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PrivateKeyBase {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = into_bstring(untagged_cbor)?;
        let instance = Self::from_data_ref(&data);
        Ok(instance)
    }
}

impl URDecodable for PrivateKeyBase { }

impl URCodable for PrivateKeyBase { }

#[cfg(test)]
mod tests {
    use bc_ur::{UREncodable, URDecodable};
    use hex_literal::hex;

    use crate::PrivateKeyBase;

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    fn test_private_key_base() {
        let private_key_base = PrivateKeyBase::from_data(&SEED);
        assert_eq!(private_key_base.signing_private_key().data(), &hex!("9505a44aaf385ce633cf0e2bc49e65cc88794213bdfbf8caf04150b9c4905f5a"));
        assert_eq!(private_key_base.signing_private_key().schnorr_public_key().schnorr().unwrap().data(), &hex!("fd4d22f9e8493da52d730aa402ac9e661deca099ef4db5503f519a73c3493e18"));
        assert_eq!(private_key_base.agreement_private_key().data(), &hex!("77ff838285a0403d3618aa8c30491f99f55221be0b944f50bfb371f43b897485"));
        assert_eq!(private_key_base.agreement_private_key().public_key().data(), &hex!("863cf3facee3ba45dc54e5eedecb21d791d64adfb0a1c63bfb6fea366c1ee62b"));

        let ur = private_key_base.ur_string();
        assert_eq!(ur, "ur:crypto-prvkeys/gdhkwzdtfthptokigtvwnnjsqzcxknsktdsfecsbbk");
        assert_eq!(PrivateKeyBase::from_ur_string(&ur).unwrap(), private_key_base);
    }
}
