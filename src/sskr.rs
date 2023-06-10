use bc_crypto::RandomNumberGenerator;
use dcbor::{CBORTagged, Tag, CBOREncodable, CBORTaggedEncodable, CBOR, CBORDecodable, CBORTaggedDecodable};
use bc_ur::{UREncodable, URDecodable, URCodable};
use crate::tags;
pub use bc_sskr::{Spec as SSKRSpec, GroupSpec as SSKRGroupSpec, Secret as SSKRSecret, Error as SSKRError };

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct SSKRShare(Vec<u8>);

impl SSKRShare {
    pub fn from_data_ref<T>(data: &T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self(data.as_ref().to_vec())
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn from_hex<T>(hex: T) -> Self where T: AsRef<str> {
        Self::from_data_ref(&hex::decode(hex.as_ref()).unwrap())
    }

    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl SSKRShare {
    pub fn identifier(&self) -> u16 {
        (u16::from(self.0[0]) << 8) | u16::from(self.0[1])
    }

    pub fn identifier_hex(&self) -> String {
        hex::encode(&self.0[0..=1])
    }

    pub fn group_threshold(&self) -> usize {
        usize::from(self.0[2] >> 4) + 1
    }

    pub fn group_count(&self) -> usize {
        usize::from(self.0[2] & 0xf) + 1
    }

    pub fn group_index(&self) -> usize {
        usize::from(self.0[3] >> 4)
    }

    pub fn member_threshold(&self) -> usize {
        usize::from(self.0[3] & 0xf) + 1
    }

    pub fn member_index(&self) -> usize {
        usize::from(self.0[4] & 0xf)
    }
}

impl CBORTagged for SSKRShare {
    const CBOR_TAG: Tag = tags::SSKR_SHARE;
}

impl CBOREncodable for SSKRShare {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl CBORTaggedEncodable for SSKRShare {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::byte_string(&self.0)
    }
}

impl UREncodable for SSKRShare { }

impl CBORDecodable for SSKRShare {
    fn from_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SSKRShare {
    fn from_untagged_cbor(cbor: &CBOR) -> Result<Self, dcbor::Error> {
        let data = CBOR::expect_byte_string(cbor)?;
        let instance = Self::from_data_ref(&data);
        Ok(instance)
    }
}

impl URDecodable for SSKRShare { }

impl URCodable for SSKRShare { }

pub fn sskr_generate(
    spec: &SSKRSpec,
    master_secret: &SSKRSecret,
) -> Result<Vec<Vec<SSKRShare>>, SSKRError> {
    let mut rng = bc_crypto::SecureRandomNumberGenerator;
    sskr_generate_using(spec, master_secret, &mut rng)
}

pub fn sskr_generate_using(
    spec: &SSKRSpec,
    master_secret: &SSKRSecret,
    rng: &mut impl RandomNumberGenerator,
) -> Result<Vec<Vec<SSKRShare>>, SSKRError> {
    let shares = bc_sskr::sskr_generate_using(spec, master_secret, rng)?;
    let shares = shares.into_iter().map(|group| {
        group.into_iter().map(|share| {
            SSKRShare::from_data_ref(&share)
        }).collect()
    }).collect();
    Ok(shares)
}

pub fn sskr_combine(shares: &[SSKRShare]) -> Result<SSKRSecret, SSKRError>
{
    let shares: Vec<Vec<u8>> = shares.iter().map(|share| share.data().to_vec()).collect();
    bc_sskr::sskr_combine(&shares)
}
