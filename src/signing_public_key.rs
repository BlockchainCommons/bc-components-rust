use crate::{SchnorrPublicKey, ECPublicKey, tags_registry, ECKeyBase, Signature};
use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{Tag, CBORTagged, CBOREncodable, CBORTaggedEncodable, CBORDecodable, CBORTaggedDecodable, CBOR, byte_string, from_byte_string};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SigningPublicKey {
    Schnorr(SchnorrPublicKey),
    ECDSA(ECPublicKey),
}

impl SigningPublicKey {
    pub fn from_schnorr(key: SchnorrPublicKey) -> Self {
        Self::Schnorr(key)
    }

    pub fn from_ecdsa(key: ECPublicKey) -> Self {
        Self::ECDSA(key)
    }

    pub fn schnorr(&self) -> Option<&SchnorrPublicKey> {
        match self {
            Self::Schnorr(key) => Some(key),
            _ => None,
        }
    }

    pub fn ecdsa(&self) -> Option<&ECPublicKey> {
        match self {
            Self::ECDSA(key) => Some(key),
            _ => None,
        }
    }

    pub fn verify<D>(&self, signature: &Signature, message: D) -> bool
    where
        D: AsRef<[u8]>,
    {
        match self {
            SigningPublicKey::Schnorr(key) => {
                match signature {
                    Signature::Schnorr { sig, tag } => key.schnorr_verify(sig, message, tag),
                    Signature::ECDSA(_) => false,
                }
            },
            SigningPublicKey::ECDSA(key) => {
                match signature {
                    Signature::Schnorr { .. } => false,
                    Signature::ECDSA(sig) => key.verify(sig, message),
                }
            },
        }
    }
}

impl CBORTagged for SigningPublicKey {
    const CBOR_TAG: Tag = tags_registry::SIGNING_PUBLIC_KEY;
}

impl CBOREncodable for SigningPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SigningPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            SigningPublicKey::Schnorr(key) => {
                byte_string(key.data())
            },
            SigningPublicKey::ECDSA(key) => {
                vec![
                    1.cbor(),
                    byte_string(key.data()),
                ].cbor()
            },
        }
    }
}

impl UREncodable for SigningPublicKey { }

impl CBORDecodable for SigningPublicKey {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SigningPublicKey {
    fn from_untagged_cbor(untagged_cbor: &CBOR) -> Result<Self, dcbor::Error> {
        match untagged_cbor {
            CBOR::ByteString(data) => {
                Ok(Self::Schnorr(SchnorrPublicKey::from_data_ref(data).ok_or(dcbor::Error::InvalidFormat)?))
            },
            CBOR::Array(elements) => {
                if elements.len() == 2 {
                    if let CBOR::Unsigned(1) = &elements[0] {
                        if let Some(data) = from_byte_string(&elements[1]) {
                            return Ok(Self::ECDSA(ECPublicKey::from_data_ref(&data).ok_or(dcbor::Error::InvalidFormat)?));
                        }
                    }
                }
                Err(dcbor::Error::InvalidFormat)
            },
            _ => Err(dcbor::Error::InvalidFormat),
        }
    }
}

impl URDecodable for SigningPublicKey { }

impl URCodable for SigningPublicKey { }
