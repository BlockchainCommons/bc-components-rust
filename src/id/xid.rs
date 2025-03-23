use dcbor::prelude::*;
use anyhow::{ bail, Result, Error };

use crate::{tags, Digest, PrivateKeyBase, PublicKeys, Reference, ReferenceProvider, SigningPrivateKey, SigningPublicKey};

/// A XID (eXtensible IDentifier).
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
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
    pub fn new(genesis_key: impl AsRef<SigningPublicKey>) -> Self {
        let key_cbor_data = genesis_key.as_ref().to_cbor_data();
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
        self.ref_hex_short()
    }

    /// The first four bytes of the XID as upper-case ByteWords.
    pub fn bytewords_identifier(&self, prefix: bool) -> String {
        self.ref_bytewords(if prefix {Some("🅧")} else {None})
    }

    /// The first four bytes of the XID as Bytemoji.
    pub fn bytemoji_identifier(&self, prefix: bool) -> String {
        self.ref_bytemoji(if prefix {Some("🅧")} else {None})
    }
}

pub trait XIDProvider {
    fn xid(&self) -> XID;
}

impl XIDProvider for XID {
    fn xid(&self) -> XID {
        *self
    }
}

impl XIDProvider for SigningPublicKey {
    fn xid(&self) -> XID {
        XID::new(self)
    }
}

impl ReferenceProvider for XID {
    fn reference(&self) -> Reference {
        Reference::from_data(*self.data())
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
        tags_for_values(&[tags::TAG_XID])
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

impl TryFrom<&SigningPrivateKey> for XID {
    type Error = Error;

    fn try_from(key: &SigningPrivateKey) -> Result<Self, Self::Error> {
        Ok(Self::new(&key.public_key()?))
    }
}

impl From<&PublicKeys> for XID {
    fn from(key: &PublicKeys) -> Self {
        Self::new(key.signing_public_key())
    }
}

impl From<&PrivateKeyBase> for XID {
    fn from(key: &PrivateKeyBase) -> Self {
        Self::new(key.schnorr_signing_private_key().public_key().unwrap())
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

// Convert from a byte vector to an instance.
impl From<XID> for Vec<u8> {
    fn from(xid: XID) -> Self {
        xid.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ECPrivateKey, SigningPrivateKey};

    use super::*;
    use bc_ur::prelude::*;
    use hex_literal::hex;
    use indoc::indoc;

    #[test]
    fn test_xid() {
        crate::register_tags();
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
    }

    #[test]
    fn test_xid_from_key() {
        crate::register_tags();
        let private_key = SigningPrivateKey::new_schnorr(
            ECPrivateKey::from_data(
                hex!("322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")
            )
        );
        let public_key = private_key.public_key().unwrap();

        let key_cbor = public_key.to_cbor();
        assert_eq!(key_cbor.diagnostic(), indoc! {"
            40022(
                h'e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a'
            )
        "}.trim());
        assert_eq!(key_cbor.hex_annotated(), indoc! {"
            d9 9c56                                 # tag(40022) signing-public-key
                5820                                # bytes(32)
                    e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a
        "}.trim());
        let key_cbor_data = key_cbor.to_cbor_data();
        assert_eq!(key_cbor_data, hex!("d99c565820e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a"));
        let digest = Digest::from_image(&key_cbor_data);
        assert_eq!(digest.data(), &hex!("d40e0602674df1b732f5e025d04c45f2e74ed1652c5ae1740f6a5502dbbdcd47"));

        let xid = XID::new(&public_key);
        assert_eq!(format!("{:?}", xid), "XID(d40e0602674df1b732f5e025d04c45f2e74ed1652c5ae1740f6a5502dbbdcd47)");
        xid.validate(&public_key);

        assert_eq!(format!("{}", xid), "XID(d40e0602)");
        let reference = xid.reference();
        assert_eq!(format!("{reference}"), "Reference(d40e0602)");

        assert_eq!(reference.bytewords_identifier(None), "TINY BETA ATOM ALSO");
        assert_eq!(reference.bytemoji_identifier(None), "🧦 🤨 😎 😆");

        assert_eq!(digest.data(), xid.data());
    }
}
