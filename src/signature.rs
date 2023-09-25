use bc_crypto::{SCHNORR_SIGNATURE_SIZE, ECDSA_SIGNATURE_SIZE};
use bc_ur::prelude::*;
use crate::tags;
use anyhow::bail;

/// A cryptographic signature. Supports ECDSA and Schnorr.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Signature {
    Schnorr{ sig: [u8; SCHNORR_SIGNATURE_SIZE], tag: Vec<u8> },
    ECDSA([u8; ECDSA_SIGNATURE_SIZE]),
}

impl Signature {
    /// Restores a Schnorr signature from a vector of bytes.
    pub fn schnorr_from_data<D>(data: [u8; SCHNORR_SIGNATURE_SIZE], tag: D) -> Self
    where
        D: Into<Vec<u8>>,
    {
        Self::Schnorr{ sig: data, tag: tag.into() }
    }

    /// Restores a Schnorr signature from a vector of bytes.
    pub fn schnorr_from_data_ref<D1, D2>(data: D1, tag: D2) -> anyhow::Result<Self>
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
    {
        let data = data.as_ref();
        let tag = tag.as_ref();
        if data.len() != SCHNORR_SIGNATURE_SIZE {
            bail!("Invalid Schnorr signature size");
        }
        let mut arr = [0u8; SCHNORR_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::schnorr_from_data(arr, tag))
    }

    /// Restores an ECDSA signature from a vector of bytes.
    pub fn ecdsa_from_data(data: [u8; ECDSA_SIGNATURE_SIZE]) -> Self {
        Self::ECDSA(data)
    }

    /// Restores an ECDSA signature from a vector of bytes.
    pub fn ecdsa_from_data_ref<D>(data: D) -> anyhow::Result<Self>
    where
        D: AsRef<[u8]>,
    {
        let data = data.as_ref();
        if data.len() != ECDSA_SIGNATURE_SIZE {
            bail!("Invalid ECDSA signature size");
        }
        let mut arr = [0u8; ECDSA_SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::ecdsa_from_data(arr))
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signature::Schnorr{ sig: data, tag } => {
                f.debug_struct("Schnorr")
                    .field("data", &hex::encode(data))
                    .field("tag", &hex::encode(tag))
                    .finish()
            },
            Signature::ECDSA(data) => {
                f.debug_struct("ECDSA")
                    .field("data", &hex::encode(data))
                    .finish()
            },
        }
    }
}

impl AsRef<Signature> for Signature {
    fn as_ref(&self) -> &Signature {
        self
    }
}

impl CBORTagged for Signature {
    const CBOR_TAG: dcbor::Tag = tags::SIGNATURE;
}

impl CBOREncodable for Signature {
    fn cbor(&self) -> dcbor::CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for Signature {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            Signature::Schnorr{ sig: data, tag } => {
                if tag.is_empty() {
                    CBOR::byte_string(data)
                } else {
                    vec![
                        CBOR::byte_string(data),
                        CBOR::byte_string(tag),
                    ].cbor()
                }
            },
            Signature::ECDSA(data) => {
                vec![
                    1.cbor(),
                    CBOR::byte_string(data),
                ].cbor()
            },
        }
    }
}

impl UREncodable for Signature { }

impl CBORDecodable for Signature {
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for Signature {
    fn from_untagged_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        match cbor {
            CBOR::ByteString(bytes) => {
                Self::schnorr_from_data_ref(bytes, [])
            },
            CBOR::Array(elements) => {
                if elements.len() == 2 {
                    if let Some(data) = CBOR::as_byte_string(&elements[0]) {
                        if let Some(tag) = CBOR::as_byte_string(&elements[1]) {
                            return Self::schnorr_from_data_ref(data, tag);
                        }
                    }
                    if let CBOR::Unsigned(1) = &elements[0] {
                        if let Some(data) = CBOR::as_byte_string(&elements[1]) {
                            return Self::ecdsa_from_data_ref(data);
                        }
                    }
                }
                bail!("Invalid signature format");
            },
            _ => bail!("Invalid signature format"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{SigningPrivateKey, Signature};
    use bc_rand::make_fake_random_number_generator;
    use dcbor::{CBOREncodable, CBOR, CBORTaggedDecodable};
    use hex_literal::hex;
    use indoc::indoc;

    const SIGNING_PRIVATE_KEY: SigningPrivateKey = SigningPrivateKey::from_data(hex!("322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36"));
    const MESSAGE: &[u8] = b"Wolf McNally";

    #[test]
    fn test_schnorr_signing() {
        let public_key = SIGNING_PRIVATE_KEY.schnorr_public_key();
        let signature = SIGNING_PRIVATE_KEY.schnorr_sign(MESSAGE, vec![]);

        assert!(public_key.verify(&signature, MESSAGE));
        assert!(!public_key.verify(&signature, b"Wolf Mcnally"));

        let another_signature = SIGNING_PRIVATE_KEY.schnorr_sign(MESSAGE, vec![]);
        assert_ne!(signature, another_signature);
        assert!(public_key.verify(&another_signature, MESSAGE));
    }

    #[test]
    fn test_schnorr_cbor() {
        let mut rng = make_fake_random_number_generator();
        let signature = SIGNING_PRIVATE_KEY.schnorr_sign_using(MESSAGE, vec![], &mut rng);
        let tagged_cbor_data = signature.cbor_data();
        assert_eq!(CBOR::from_data(&tagged_cbor_data).unwrap().diagnostic(),
        indoc!{r#"
        40020(
           h'c67bb76d5d85327a771819bb6d417ffc319737a4be8248b2814ba4fd1474494200a522fd9d2a7beccc3a05cdd527a84a8c731a43669b618d831a08104f77d82f'
        )
        "#}.trim());
        let received_signature = Signature::from_tagged_cbor_data(&tagged_cbor_data).unwrap();
        assert_eq!(signature, received_signature);
    }

    #[test]
    fn test_ecdsa_signing() {
        let public_key = SIGNING_PRIVATE_KEY.ecdsa_public_key();
        let signature = SIGNING_PRIVATE_KEY.ecdsa_sign(&MESSAGE);

        assert!(public_key.verify(&signature, MESSAGE));
        assert!(!public_key.verify(&signature, b"Wolf Mcnally"));

        let another_signature = SIGNING_PRIVATE_KEY.ecdsa_sign(&MESSAGE);
        assert_eq!(signature, another_signature);
        assert!(public_key.verify(&another_signature, MESSAGE));
    }

    #[test]
    fn test_ecdsa_cbor() {
        let signature = SIGNING_PRIVATE_KEY.ecdsa_sign(&MESSAGE);
        let tagged_cbor_data = signature.cbor_data();
        assert_eq!(CBOR::from_data(&tagged_cbor_data).unwrap().diagnostic(),
        indoc!{r#"
        40020(
           [
              1,
              h'1458d0f3d97e25109b38fd965782b43213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fba4dc355cd89b47213e855cf6d23'
           ]
        )
        "#}.trim());
        let received_signature = Signature::from_tagged_cbor_data(&tagged_cbor_data).unwrap();
        assert_eq!(signature, received_signature);
    }
}
