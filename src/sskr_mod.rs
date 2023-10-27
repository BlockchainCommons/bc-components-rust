use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use bc_ur::prelude::*;
use bytes::Bytes;
use sskr::SSKRError;
use crate::tags;
pub use sskr::{Spec as SSKRSpec, GroupSpec as SSKRGroupSpec, Secret as SSKRSecret };

/// An SSKR share.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct SSKRShare(Bytes);

impl SSKRShare {
    /// Restores an `SSKRShare` from a vector of bytes.
    pub fn from_data(data: impl Into<Bytes>) -> Self {
        Self(data.into())
    }

    /// Returns the data of this `SSKRShare`.
    pub fn data(&self) -> &Bytes {
        &self.0
    }

    /// Restores an `SSKRShare` from a hex string.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data(hex::decode(hex.as_ref()).unwrap())
    }

    /// Returns the data of this `SSKRShare` as a hex string.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl SSKRShare {
    /// Returns the unique identifier of the split to which this share belongs.
    pub fn identifier(&self) -> u16 {
        (u16::from(self.0[0]) << 8) | u16::from(self.0[1])
    }

    /// Returns the unique identifier of the split to which this share belongs as a hex string.
    pub fn identifier_hex(&self) -> String {
        hex::encode(&self.0[0..=1])
    }

    /// Returns the minimum number of groups whose quorum must be met to
    /// reconstruct the secret.
    pub fn group_threshold(&self) -> usize {
        usize::from(self.0[2] >> 4) + 1
    }

    pub fn group_count(&self) -> usize {
        usize::from(self.0[2] & 0xf) + 1
    }

    /// Returns the index of the group to which this share belongs.
    pub fn group_index(&self) -> usize {
        usize::from(self.0[3] >> 4)
    }

    /// Returns the minimum number of shares within the group
    /// to which this share belongs that must be combined to meet
    /// the group threshold.
    pub fn member_threshold(&self) -> usize {
        usize::from(self.0[3] & 0xf) + 1
    }

    /// Returns the index of this share within the group to which it belongs.
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
    fn from_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl TryFrom<&CBOR> for SSKRShare {
    type Error = anyhow::Error;

    fn try_from(cbor: &CBOR) -> Result<Self, Self::Error> {
        SSKRShare::from_cbor(cbor)
    }
}

impl CBORTaggedDecodable for SSKRShare {
    fn from_untagged_cbor(cbor: &CBOR) -> anyhow::Result<Self> {
        let data = CBOR::expect_byte_string(cbor)?;
        let instance = Self::from_data(data);
        Ok(instance)
    }
}

impl URDecodable for SSKRShare { }

impl URCodable for SSKRShare { }

/// Generates SSKR shares for the given `Spec` and `Secret`.
///
/// # Arguments
///
/// * `spec` - The `Spec` instance that defines the group and member thresholds.
/// * `master_secret` - The `Secret` instance to be split into shares.
pub fn sskr_generate(
    spec: &SSKRSpec,
    master_secret: &SSKRSecret,
) -> Result<Vec<Vec<SSKRShare>>, SSKRError> {
    let mut rng = SecureRandomNumberGenerator;
    sskr_generate_using(spec, master_secret, &mut rng)
}

/// Generates SSKR shares for the given `Spec` and `Secret` using the provided
/// random number generator.
///
/// # Arguments
///
/// * `spec` - The `Spec` instance that defines the group and member thresholds.
/// * `master_secret` - The `Secret` instance to be split into shares.
/// * `random_generator` - The random number generator to use for generating
///   shares.
pub fn sskr_generate_using(
    spec: &SSKRSpec,
    master_secret: &SSKRSecret,
    rng: &mut impl RandomNumberGenerator,
) -> Result<Vec<Vec<SSKRShare>>, SSKRError> {
    let shares = sskr::sskr_generate_using(spec, master_secret, rng)?;
    let shares = shares.into_iter().map(|group| {
        group.into_iter().map(|share| {
            SSKRShare::from_data(share)
        }).collect()
    }).collect();
    Ok(shares)
}

/// Combines the given SSKR shares into a `Secret`.
///
/// # Arguments
///
/// * `shares` - A slice of SSKR shares to be combined.
///
/// # Errors
///
/// Returns an error if the shares do not meet the necessary quorum of groups
/// and member shares within each group.
pub fn sskr_combine(shares: &[SSKRShare]) -> Result<SSKRSecret, SSKRError>
{
    let shares: Vec<Vec<u8>> = shares.iter().map(|share| share.data().to_vec()).collect();
    sskr::sskr_combine(&shares)
}
