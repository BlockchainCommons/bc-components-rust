use anyhow::{Error, Result, bail};
use dcbor::prelude::*;

use crate::{
    Digest, PrivateKeyBase, PublicKeys, Reference, ReferenceProvider,
    SigningPrivateKey, SigningPublicKey, tags,
};

/// A XID (eXtensible IDentifier).
///
/// A XID is a unique 32-byte identifier for a subject entity (person,
/// organization, device, or any other entity). XIDs have the following
/// characteristics:
///
/// - They're cryptographically tied to a public key at inception (the
///   "inception key")
/// - They remain stable throughout their lifecycle even as their keys and
///   permissions change
/// - They can be extended to XID documents containing keys, endpoints,
///   permissions, and delegation info
/// - They support key rotation and multiple verification schemes
/// - They allow for delegation of specific permissions to other entities
/// - They can include resolution methods to locate and verify the XID document
///
/// A XID is created by taking the SHA-256 hash of the CBOR encoding of a public
/// signing key. This ensures the XID is cryptographically tied to the key.
///
/// As defined in [BCR-2024-010](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2024-010-xid.md).
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct XID([u8; Self::XID_SIZE]);

impl XID {
    pub const XID_SIZE: usize = 32;

    /// Create a new XID from data.
    pub fn from_data(data: [u8; Self::XID_SIZE]) -> Self { Self(data) }

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
    pub fn data(&self) -> &[u8; Self::XID_SIZE] { self.into() }

    /// Get the data of the XID as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

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
    pub fn to_hex(&self) -> String { hex::encode(self.0) }

    /// The first four bytes of the XID as a hexadecimal string.
    pub fn short_description(&self) -> String { self.ref_hex_short() }

    /// The first four bytes of the XID as upper-case ByteWords.
    pub fn bytewords_identifier(&self, prefix: bool) -> String {
        self.ref_bytewords(if prefix { Some("🅧") } else { None })
    }

    /// The first four bytes of the XID as Bytemoji.
    pub fn bytemoji_identifier(&self, prefix: bool) -> String {
        self.ref_bytemoji(if prefix { Some("🅧") } else { None })
    }
}

/// A provider trait for obtaining XIDs from various objects.
pub trait XIDProvider {
    /// Returns the XID for this object.
    fn xid(&self) -> XID;
}

/// Implements XIDProvider for XID to return itself.
impl XIDProvider for XID {
    fn xid(&self) -> XID { *self }
}

/// Implements XIDProvider for SigningPublicKey to generate an XID from the key.
impl XIDProvider for SigningPublicKey {
    fn xid(&self) -> XID { XID::new(self) }
}

/// Implements ReferenceProvider for XID to generate a Reference from the XID.
impl ReferenceProvider for XID {
    fn reference(&self) -> Reference { Reference::from_data(*self.data()) }
}

/// Implements conversion from a XID reference to a byte array reference.
impl<'a> From<&'a XID> for &'a [u8; XID::XID_SIZE] {
    fn from(value: &'a XID) -> Self { &value.0 }
}

/// Implements conversion from a XID reference to a byte slice reference.
impl<'a> From<&'a XID> for &'a [u8] {
    fn from(value: &'a XID) -> Self { &value.0 }
}

/// Implements AsRef<[u8]> to allow XID to be treated as a byte slice.
impl AsRef<[u8]> for XID {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements PartialOrd to allow XIDs to be compared and partially ordered.
impl std::cmp::PartialOrd for XID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

/// Implements Ord to allow XIDs to be fully ordered.
impl std::cmp::Ord for XID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.0.cmp(&other.0) }
}

/// Implements Debug formatting for XID showing the full hex representation.
impl std::fmt::Debug for XID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XID({})", hex::encode(self.0))
    }
}

/// Implements Display formatting for XID showing a shortened hex
/// representation.
impl std::fmt::Display for XID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XID({})", self.short_description())
    }
}

/// Implements CBORTagged trait to provide CBOR tag information for XID.
impl CBORTagged for XID {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[tags::TAG_XID]) }
}

/// Implements conversion from XID to CBOR for serialization.
impl From<XID> for CBOR {
    fn from(value: XID) -> Self { value.tagged_cbor() }
}

/// Implements conversion from SigningPublicKey reference to XID.
impl From<&SigningPublicKey> for XID {
    fn from(key: &SigningPublicKey) -> Self { Self::new(key) }
}

/// Implements conversion from SigningPrivateKey reference to XID via the public
/// key.
impl TryFrom<&SigningPrivateKey> for XID {
    type Error = Error;

    fn try_from(key: &SigningPrivateKey) -> Result<Self, Self::Error> {
        Ok(Self::new(&key.public_key()?))
    }
}

/// Implements conversion from PublicKeys reference to XID via the signing
/// public key.
impl From<&PublicKeys> for XID {
    fn from(key: &PublicKeys) -> Self { Self::new(key.signing_public_key()) }
}

/// Implements conversion from PrivateKeyBase reference to XID via the Schnorr
/// signing key.
impl From<&PrivateKeyBase> for XID {
    fn from(key: &PrivateKeyBase) -> Self {
        Self::new(key.schnorr_signing_private_key().public_key().unwrap())
    }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality for
/// XID.
impl CBORTaggedEncodable for XID {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.0) }
}

/// Implements conversion from CBOR to XID for deserialization.
impl TryFrom<CBOR> for XID {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality for
/// XID.
impl CBORTaggedDecodable for XID {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Ok(Self::from_data_ref(data)?)
    }
}

/// Implements conversion from XID to `Vec<u8>` to allow access to the raw
/// bytes.
impl From<XID> for Vec<u8> {
    fn from(xid: XID) -> Self { xid.0.to_vec() }
}

#[cfg(test)]
mod tests {
    use bc_ur::prelude::*;
    use hex_literal::hex;
    use indoc::indoc;

    use super::*;
    use crate::{ECPrivateKey, SigningPrivateKey};

    #[test]
    fn test_xid() {
        crate::register_tags();
        let xid = XID::from_data_ref(hex!(
            "de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037"
        ))
        .unwrap();
        assert_eq!(
            xid.to_hex(),
            "de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037"
        );
        assert_eq!(xid.short_description(), "de285368");
        assert_eq!(
            xid.data(),
            &hex!(
                "de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037"
            )
        );
        assert_eq!(
            format!("{:?}", xid),
            "XID(de2853684ae55803a08b36dd7f4e566649970601927330299fd333f33fecc037)"
        );
        assert_eq!(format!("{}", xid), "XID(de285368)");

        let xid_string = xid.ur_string();
        assert_eq!(
            xid_string,
            "ur:xid/hdcxuedeguisgevwhdaxnbluenutlbglhfiygamsamadmojkdydtneteeowffhwprtemcaatledk"
        );
        assert_eq!(XID::from_ur_string(xid_string).unwrap(), xid);
        assert_eq!(xid.bytewords_identifier(true), "🅧 URGE DICE GURU IRIS");
        assert_eq!(xid.bytemoji_identifier(true), "🅧 🐻 😻 🍞 💐");
    }

    #[test]
    fn test_xid_from_key() {
        crate::register_tags();
        let private_key = SigningPrivateKey::new_schnorr(
            ECPrivateKey::from_data(hex!(
                "322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36"
            )),
        );
        let public_key = private_key.public_key().unwrap();

        let key_cbor = public_key.to_cbor();
        #[rustfmt::skip]
        assert_eq!(key_cbor.diagnostic(), indoc! {"
            40022(
                h'e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a'
            )
        "}.trim());
        #[rustfmt::skip]
        assert_eq!(key_cbor.hex_annotated(), indoc! {"
            d9 9c56                                 # tag(40022) signing-public-key
                5820                                # bytes(32)
                    e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a
        "}.trim());
        let key_cbor_data = key_cbor.to_cbor_data();
        assert_eq!(
            key_cbor_data,
            hex!(
                "d99c565820e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a"
            )
        );
        let digest = Digest::from_image(&key_cbor_data);
        assert_eq!(
            digest.data(),
            &hex!(
                "d40e0602674df1b732f5e025d04c45f2e74ed1652c5ae1740f6a5502dbbdcd47"
            )
        );

        let xid = XID::new(&public_key);
        assert_eq!(
            format!("{:?}", xid),
            "XID(d40e0602674df1b732f5e025d04c45f2e74ed1652c5ae1740f6a5502dbbdcd47)"
        );
        xid.validate(&public_key);

        assert_eq!(format!("{}", xid), "XID(d40e0602)");
        let reference = xid.reference();
        assert_eq!(format!("{reference}"), "Reference(d40e0602)");

        assert_eq!(reference.bytewords_identifier(None), "TINY BETA ATOM ALSO");
        assert_eq!(reference.bytemoji_identifier(None), "🧦 🤨 😎 😆");

        assert_eq!(digest.data(), xid.data());
    }
}
