use dcbor::prelude::*;
use anyhow::{ bail, Result, Error };

use crate::{tags, Digest, PrivateKeyBase, PublicKeyBase, SigningPrivateKey, SigningPublicKey};
use bc_ur::prelude::*;

/// A XID (eXtensible IDentifier).
#[derive(Clone, Eq, PartialEq)]
pub struct XID([u8; Self::XID_SIZE]);

impl XID {
    pub const XID_SIZE: usize = 32;

    /// Create a new XID from data.
    pub fn from_data(data: [u8; Self::XID_SIZE]) -> Self {
        Self(data)
    }

    /// Create a new XID from data.
    ///
    /// Returns `None` if the data is not the correct length.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::XID_SIZE {
            bail!("Invalid XID size");
        }
        let mut arr = [0u8; Self::XID_SIZE];
        arr.copy_from_slice(data.as_ref());
        Ok(Self::from_data(arr))
    }

    /// Return the data of the XID.
    pub fn data(&self) -> &[u8; Self::XID_SIZE] {
        self.into()
    }

    /// Create a new XID from the given public key (the "genesis key").
    ///
    /// The XID is the SHA-256 digest of the CBOR encoding of the public key.
    pub fn new(genesis_key: &SigningPublicKey) -> Self {
        let key_cbor_data = genesis_key.to_cbor_data();
        let digest = Digest::from_image(key_cbor_data);
        Self::from_data(*digest.data())
    }

    /// Validate the XID against the given public key.
    pub fn validate(&self, key: &SigningPublicKey) -> bool {
        let key_data = key.to_cbor_data();
        let digest = Digest::from_image(key_data);
        *digest.data() == self.0
    }

    /// Create a new XID from the given hexadecimal string.
    ///
    /// # Panics
    /// Panics if the string is not exactly 64 hexadecimal digits.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// The data as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The first four bytes of the XID as a hexadecimal string.
    pub fn short_description(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// The first four bytes of the XID as upper-case ByteWords.
    pub fn bytewords_identifier(&self, prefix: bool) -> String {
        let s = bytewords::identifier(&self.0[..4].try_into().unwrap()).to_uppercase();
        if prefix {
            format!("🅧 {}", s)
        } else {
            s
        }
    }

    /// The first four bytes of the XID as Bytemoji.
    pub fn bytemoji_identifier(&self, prefix: bool) -> String {
        let s = bytewords::bytemoji_identifier(&self.0[..4].try_into().unwrap()).to_uppercase();
        if prefix {
            format!("🅧 {}", s)
        } else {
            s
        }
    }

    /// The entire CBOR of the XID, run through SHA-256.
    pub fn lifehash_fingerprint(&self) -> Digest {
        Digest::from_image(self.to_cbor().to_cbor_data())
    }
}

impl<'a> From<&'a XID> for &'a [u8; XID::XID_SIZE] {
    fn from(value: &'a XID) -> Self {
        &value.0
    }
}

impl<'a> From<&'a XID> for &'a [u8] {
    fn from(value: &'a XID) -> Self {
        &value.0
    }
}

impl AsRef<[u8]> for XID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<XID> for XID {
    fn as_ref(&self) -> &XID {
        self
    }
}

impl std::cmp::PartialOrd for XID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl std::cmp::Ord for XID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Debug for XID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XID({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for XID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XID({})", self.short_description())
    }
}

impl CBORTagged for XID {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::XID]
    }
}

impl From<XID> for CBOR {
    fn from(value: XID) -> Self {
        value.tagged_cbor()
    }
}

impl From<&SigningPublicKey> for XID {
    fn from(key: &SigningPublicKey) -> Self {
        Self::new(key)
    }
}

impl From<&SigningPrivateKey> for XID {
    fn from(key: &SigningPrivateKey) -> Self {
        Self::new(&key.public_key())
    }
}

impl From<&PublicKeyBase> for XID {
    fn from(key: &PublicKeyBase) -> Self {
        Self::new(key.signing_public_key())
    }
}

impl From<&PrivateKeyBase> for XID {
    fn from(key: &PrivateKeyBase) -> Self {
        Self::new(&key.schnorr_signing_private_key().public_key())
    }
}

impl CBORTaggedEncodable for XID {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.0)
    }
}

impl TryFrom<CBOR> for XID {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for XID {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Self::from_data_ref(data)
    }
}

// Convert from an instance reference to an instance.
impl From<&XID> for XID {
    fn from(xid: &XID) -> Self {
        xid.clone()
    }
}

// Convert from a byte vector to an instance.
impl From<XID> for Vec<u8> {
    fn from(xid: XID) -> Self {
        xid.0.to_vec()
    }
}

// Convert a reference to an instance to a byte vector.
impl From<&XID> for Vec<u8> {
    fn from(xid: &XID) -> Self {
        xid.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ECPrivateKey, SigningPrivateKey};

    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_xid() {
        let xid = XID::from_data_ref(hex!("de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037")).unwrap();
        assert_eq!(xid.to_hex(), "de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037");
        assert_eq!(xid.short_description(), "de285368");
        assert_eq!(xid.data(), &hex!("de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037"));
        assert_eq!(format!("{:?}", xid), "XID(de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037)");
        assert_eq!(format!("{}", xid), "XID(de285368)");

        let xid_string = xid.ur_string();
        assert_eq!(xid_string, "ur:xid/hdcxuedeguisgevwhdaxnbluenutlbglhfiygamsamadmojkdydtneteeowffhwprtemcaatledk");
        assert_eq!(XID::from_ur_string(xid_string).unwrap(), xid);
        assert_eq!(xid.bytewords_identifier(true), "🅧 URGE DICE GURU IRIS");
        assert_eq!(xid.bytemoji_identifier(true), "🅧 🐻 😻 🍞 💐");
        assert_eq!(format!("{}", xid.lifehash_fingerprint()), "Digest(e9d80e53f996dd89fac0155b27ed78b1cce10bf2d3581773eee9cbdf9a4a797f)");
    }

    #[test]
    fn test_xid_from_key() {
        let private_key = SigningPrivateKey::new_schnorr(
            ECPrivateKey::from_data(
                hex!("322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")
            )
        );
        let public_key = private_key.public_key();
        let xid = XID::new(&public_key);
        assert_eq!(format!("{:?}", xid), "XID(d40e0602674df1b732f5e025d04c45f2e74ed1652c5ae1740f6a5502dbbdcd47)");
        xid.validate(&public_key);
    }
}
