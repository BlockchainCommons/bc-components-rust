use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use bc_ur::prelude::*;
use bytes::Bytes;

use crate::{PrivateKeysDataProvider, SigningPrivateKey, AgreementPrivateKey, PublicKeyBase, tags};

/// Holds unique data from which keys for signing and encryption can be derived.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKeyBase(Bytes);

impl PrivateKeyBase {
    /// Generate a new random `PrivateKeyBase`.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Restores a `PrivateKeyBase` from bytes.
    pub fn from_data(data: impl Into<Bytes>) -> Self {
        Self(data.into())
    }

    /// Restores a `PrivateKeyBase` from an optional reference to a vector of bytes.
    ///
    /// If the data is `None`, a new random `PrivateKeyBase` is generated.
    pub fn from_optional_data(data: Option<impl Into<Bytes>>) -> Self {
        match data {
            Some(data) => Self::from_data(data),
            None => Self::new(),
        }
    }

    /// Generate a new random `PrivateKeyBase` using the given random number generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self::from_data(rng.random_data(32))
    }

    /// Create a new `PrivateKeyBase` from the given private keys data provider.
    pub fn new_with_provider(provider: impl PrivateKeysDataProvider) -> Self {
        Self::from_data(provider.private_keys_data())
    }

    /// Derive a new `SigningPrivateKey` from this `PrivateKeyBase`.
    pub fn signing_private_key(&self) -> SigningPrivateKey {
        SigningPrivateKey::derive_from_key_material(&self.0)
    }

    /// Derive a new `AgreementPrivateKey` from this `PrivateKeyBase`.
    pub fn agreement_private_key(&self) -> AgreementPrivateKey {
        AgreementPrivateKey::derive_from_key_material(&self.0)
    }

    /// Derive a new `PublicKeyBase` from this `PrivateKeyBase`.
    ///
    /// This is a Schnorr public key for signing.
    pub fn public_keys(&self) -> PublicKeyBase {
        PublicKeyBase::new(self.signing_private_key().schnorr_public_key(), self.agreement_private_key().public_key())
    }

    /// Derive a new `PublicKeyBase` from this `PrivateKeyBase`.
    ///
    /// This is an ECDSA public key for signing.
    pub fn ecdsa_public_keys(&self) -> PublicKeyBase {
        PublicKeyBase::new(self.signing_private_key().ecdsa_public_key(), self.agreement_private_key().public_key())
    }

    /// Get the raw data of this `PrivateKeyBase`.
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
        vec![tags::PRIVATE_KEY_BASE]
    }
}

impl CBOREncodable for PrivateKeyBase {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl From<PrivateKeyBase> for CBOR {
    fn from(value: PrivateKeyBase) -> Self {
        value.cbor()
    }
}

impl CBORTaggedEncodable for PrivateKeyBase {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(&self.0)
    }
}

impl UREncodable for PrivateKeyBase { }

impl CBORDecodable for PrivateKeyBase {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl TryFrom<CBOR> for PrivateKeyBase {
    type Error = anyhow::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(&cbor)
    }
}

impl TryFrom<&CBOR> for PrivateKeyBase {
    type Error = anyhow::Error;

    fn try_from(cbor: &CBOR) -> Result<Self, Self::Error> {
        Self::from_cbor(cbor)
    }
}

impl CBORTaggedDecodable for PrivateKeyBase {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> anyhow::Result<Self> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data(data);
        Ok(instance)
    }
}

impl URDecodable for PrivateKeyBase { }

impl URCodable for PrivateKeyBase { }

#[cfg(test)]
mod tests {
    use bc_ur::{UREncodable, URDecodable};
    use bytes::Bytes;
    use hex_literal::hex;

    use crate::PrivateKeyBase;

    const SEED: [u8; 16] = hex!("59f2293a5bce7d4de59e71b4207ac5d2");

    #[test]
    fn test_private_key_base() {
        let private_key_base = PrivateKeyBase::from_data(Bytes::from_static(&SEED));
        assert_eq!(private_key_base.signing_private_key().data(), &hex!("9505a44aaf385ce633cf0e2bc49e65cc88794213bdfbf8caf04150b9c4905f5a"));
        assert_eq!(private_key_base.signing_private_key().schnorr_public_key().schnorr().unwrap().data(), &hex!("fd4d22f9e8493da52d730aa402ac9e661deca099ef4db5503f519a73c3493e18"));
        assert_eq!(private_key_base.agreement_private_key().data(), &hex!("77ff838285a0403d3618aa8c30491f99f55221be0b944f50bfb371f43b897485"));
        assert_eq!(private_key_base.agreement_private_key().public_key().data(), &hex!("863cf3facee3ba45dc54e5eedecb21d791d64adfb0a1c63bfb6fea366c1ee62b"));

        let ur = private_key_base.ur_string();
        assert_eq!(ur, "ur:crypto-prvkeys/gdhkwzdtfthptokigtvwnnjsqzcxknsktdsfecsbbk");
        assert_eq!(PrivateKeyBase::from_ur_string(&ur).unwrap(), private_key_base);
    }
}
