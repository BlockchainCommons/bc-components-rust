use std::rc::Rc;
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR};
use crate::tags;

/// A Curve25519 public key used for X25519 key agreement.
///
/// <https://datatracker.ietf.org/doc/html/rfc7748>
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgreementPublicKey ([u8; Self::KEY_SIZE]);

impl AgreementPublicKey {
    pub const KEY_SIZE: usize = 32;

    /// Restore an `AgreementPublicKey` from a fixed-size array of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restore an `AgreementPublicKey` from a reference to an array of bytes.
    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            return None;
        }
        let mut arr = [0u8; Self::KEY_SIZE];
        arr.copy_from_slice(data);
        Some(Self::from_data(arr))
    }

    /// Get a reference to the fixed-size array of bytes.
    pub fn data(&self) -> &[u8; Self::KEY_SIZE] {
        self.into()
    }

    /// Restore an `AgreementPublicKey` from a hex string.
    ///
    /// # Panics
    ///
    /// Panics if the hex string is invalid or the length is not `AgreementPublicKey::KEY_SIZE * 2`.
    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// Get the hex string representation of the `AgreementPublicKey`.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl From<Rc<AgreementPublicKey>> for AgreementPublicKey {
    fn from(value: Rc<AgreementPublicKey>) -> Self {
        value.as_ref().clone()
    }
}

impl<'a> From<&'a AgreementPublicKey> for &'a [u8; AgreementPublicKey::KEY_SIZE] {
    fn from(value: &'a AgreementPublicKey) -> Self {
        &value.0
    }
}

impl CBORTagged for AgreementPublicKey {
    const CBOR_TAG: Tag = tags::AGREEMENT_PUBLIC_KEY;
}

impl CBOREncodable for AgreementPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for AgreementPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(self.data())
    }
}

impl CBORDecodable for AgreementPublicKey {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for AgreementPublicKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = CBOR::expect_byte_string(untagged_cbor)?;
        let instance = Self::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?;
        Ok(instance)
    }
}

impl UREncodable for AgreementPublicKey { }

impl URDecodable for AgreementPublicKey { }

impl URCodable for AgreementPublicKey { }

impl std::fmt::Debug for AgreementPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgreementPublicKey({})", self.hex())
    }
}

// Convert from a reference to a byte vector to a AgreementPublicKey.
impl From<&AgreementPublicKey> for AgreementPublicKey {
    fn from(key: &AgreementPublicKey) -> Self {
        key.clone()
    }
}

// Convert from a byte vector to a AgreementPublicKey.
impl From<AgreementPublicKey> for Vec<u8> {
    fn from(key: AgreementPublicKey) -> Self {
        key.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a AgreementPublicKey.
impl From<&AgreementPublicKey> for Vec<u8> {
    fn from(key: &AgreementPublicKey) -> Self {
        key.0.to_vec()
    }
}
