use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use bc_ur::prelude::*;
use sskr::SSKRError;
/// Re-export of the `Spec` type from the `sskr` crate.
///
/// Describes the configuration for a Sharded Secret Key Reconstruction
/// (SSKR) split, including the group threshold and specifications for each
/// group.
pub use sskr::{
    GroupSpec as SSKRGroupSpec, Secret as SSKRSecret, Spec as SSKRSpec,
};

use crate::tags;

/// A share of a secret split using Sharded Secret Key Reconstruction (SSKR).
///
/// SSKR is a protocol for splitting a secret into multiple shares across one or
/// more groups, such that the secret can be reconstructed only when a threshold
/// number of shares from a threshold number of groups are combined.
///
/// Each SSKR share contains:
/// - A unique identifier for the split
/// - Metadata about the group structure (thresholds, counts, indices)
/// - A portion of the secret data
///
/// SSKR shares follow a specific binary format that includes a 5-byte metadata
/// header followed by the share value. The metadata encodes information about
/// group thresholds, member thresholds, and the position of this share within
/// the overall structure.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct SSKRShare(Vec<u8>);

impl SSKRShare {
    /// Creates a new `SSKRShare` from raw binary data.
    ///
    /// # Parameters
    ///
    /// * `data` - The raw binary data of the SSKR share, including both
    ///   metadata (5 bytes) and share value.
    ///
    /// # Returns
    ///
    /// A new `SSKRShare` instance containing the provided data.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// // Raw SSKR share data (typically from sskr_generate function)
    /// let data = vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]; // Example data
    /// let share = SSKRShare::from_data(data);
    /// ```
    pub fn from_data(data: impl AsRef<[u8]>) -> Self {
        Self(data.as_ref().to_vec())
    }

    /// Returns a reference to the raw binary data of this share.
    ///
    /// # Returns
    ///
    /// A reference to the byte vector containing the SSKR share data.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let data = vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]; // Example data
    /// let share = SSKRShare::from_data(data.clone());
    /// assert_eq!(share.as_bytes(), &data);
    /// ```
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Creates a new `SSKRShare` from a hexadecimal string.
    ///
    /// # Parameters
    ///
    /// * `hex` - A hexadecimal string representing the SSKR share data.
    ///
    /// # Returns
    ///
    /// A new `SSKRShare` instance created from the decoded hex data.
    ///
    /// # Panics
    ///
    /// Panics if the hex string is invalid and cannot be decoded.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_hex("1234213101aabbcc");
    /// assert_eq!(share.hex(), "1234213101aabbcc");
    /// ```
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data(hex::decode(hex.as_ref()).unwrap())
    }

    /// Returns the data of this `SSKRShare` as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// A hex-encoded string representing the SSKR share data.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![
    ///     0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC,
    /// ]);
    /// assert_eq!(share.hex(), "1234213101aabbcc");
    /// ```
    pub fn hex(&self) -> String { hex::encode(self.as_bytes()) }

    /// Returns the unique identifier of the split to which this share belongs.
    ///
    /// The identifier is a 16-bit value that is the same for all shares in a
    /// split and is used to verify that shares belong together when
    /// combining them.
    ///
    /// # Returns
    ///
    /// A 16-bit integer representing the unique identifier of the split.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![
    ///     0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC,
    /// ]);
    /// assert_eq!(share.identifier(), 0x1234);
    /// ```
    pub fn identifier(&self) -> u16 {
        (u16::from(self.0[0]) << 8) | u16::from(self.0[1])
    }

    /// Returns the unique identifier of the split as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// A hexadecimal string representing the 16-bit identifier.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![
    ///     0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC,
    /// ]);
    /// assert_eq!(share.identifier_hex(), "1234");
    /// ```
    pub fn identifier_hex(&self) -> String { hex::encode(&self.0[0..=1]) }

    /// Returns the minimum number of groups whose quorum must be met to
    /// reconstruct the secret.
    ///
    /// This value is encoded as GroupThreshold - 1 in the metadata, so the
    /// actual threshold value is one more than the encoded value.
    ///
    /// # Returns
    ///
    /// The group threshold value (minimum number of groups required).
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]);
    /// // The encoded value 0x2 in the third byte's high nibble represents a threshold of 3
    /// assert_eq!(share.group_threshold(), 3);
    /// ```
    pub fn group_threshold(&self) -> usize { usize::from(self.0[2] >> 4) + 1 }

    /// Returns the total number of groups in the split.
    ///
    /// This value is encoded as GroupCount - 1 in the metadata, so the actual
    /// count is one more than the encoded value.
    ///
    /// # Returns
    ///
    /// The total number of groups in the split.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]);
    /// // The encoded value 0x1 in the third byte's low nibble represents a count of 2
    /// assert_eq!(share.group_count(), 2);
    /// ```
    pub fn group_count(&self) -> usize { usize::from(self.0[2] & 0xf) + 1 }

    /// Returns the index of the group to which this share belongs.
    ///
    /// This is a zero-based index identifying which group in the split this
    /// share is part of.
    ///
    /// # Returns
    ///
    /// The group index (0-based).
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]);
    /// // The encoded value 0x3 in the fourth byte's high nibble represents group index 3
    /// assert_eq!(share.group_index(), 3);
    /// ```
    pub fn group_index(&self) -> usize { usize::from(self.0[3] >> 4) }

    /// Returns the minimum number of shares within the group to which this
    /// share belongs that must be combined to meet the group threshold.
    ///
    /// This value is encoded as MemberThreshold - 1 in the metadata, so the
    /// actual threshold value is one more than the encoded value.
    ///
    /// # Returns
    ///
    /// The member threshold value (minimum number of shares required within
    /// this group).
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]);
    /// // The encoded value 0x1 in the fourth byte's low nibble represents a threshold of 2
    /// assert_eq!(share.member_threshold(), 2);
    /// ```
    pub fn member_threshold(&self) -> usize { usize::from(self.0[3] & 0xf) + 1 }

    /// Returns the index of this share within the group to which it belongs.
    ///
    /// This is a zero-based index identifying which share within the group
    /// this specific share is.
    ///
    /// # Returns
    ///
    /// The member index (0-based) within the group.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::SSKRShare;
    ///
    /// let share = SSKRShare::from_data(vec![0x12, 0x34, 0x21, 0x31, 0x01, 0xAA, 0xBB, 0xCC]);
    /// // The encoded value 0x1 in the fifth byte's low nibble represents member index 1
    /// assert_eq!(share.member_index(), 1);
    /// ```
    pub fn member_index(&self) -> usize { usize::from(self.0[4] & 0xf) }
}

impl AsRef<[u8]> for SSKRShare {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implementation of the CBOR Tagged trait for SSKRShare.
///
/// This allows SSKR shares to be serialized with specific CBOR tags that
/// identify them as SSKR shares.
impl CBORTagged for SSKRShare {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_SSKR_SHARE, tags::TAG_SSKR_SHARE_V1])
    }
}

/// Conversion from SSKRShare to CBOR for serialization.
impl From<SSKRShare> for CBOR {
    fn from(value: SSKRShare) -> Self { value.tagged_cbor() }
}

/// Implementation of CBOR encoding for SSKRShare.
impl CBORTaggedEncodable for SSKRShare {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(&self.0) }
}

/// Conversion from CBOR to SSKRShare for deserialization.
impl TryFrom<CBOR> for SSKRShare {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implementation of CBOR decoding for SSKRShare.
impl CBORTaggedDecodable for SSKRShare {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(cbor)?;
        Ok(Self::from_data(data))
    }
}

/// Generates SSKR shares for the given `Spec` and `Secret`.
///
/// This function splits a master secret into multiple shares according to the
/// specified group and member thresholds, using a secure random number
/// generator.
///
/// # Parameters
///
/// * `spec` - The `SSKRSpec` instance that defines the group threshold, number
///   of groups, and the member thresholds for each group.
/// * `master_secret` - The `SSKRSecret` instance to be split into shares.
///
/// # Returns
///
/// A result containing a nested vector of `SSKRShare` instances if successful,
/// or an `SSKRError` if the operation fails. The outer vector contains one
/// vector per group, and each inner vector contains the shares for that group.
///
/// # Errors
///
/// Returns an error if:
/// - The secret is too short or too long
/// - The group threshold is invalid
/// - The member thresholds are invalid
/// - Any other error in the underlying SSKR implementation
///
/// # Example
///
/// ```
/// use bc_components::{SSKRSecret, SSKRSpec, SSKRGroupSpec, sskr_generate};
///
/// // Create a master secret from a byte array (must be exactly 16 or 32 bytes)
/// let master_secret = SSKRSecret::new(b"0123456789abcdef").unwrap(); // Exactly 16 bytes
///
/// // Configure a split with 2 groups, requiring both groups (threshold = 2)
/// // First group: 2 of 3 shares needed
/// // Second group: 3 of 5 shares needed
/// let group1 = SSKRGroupSpec::new(2, 3).unwrap();
/// let group2 = SSKRGroupSpec::new(3, 5).unwrap();
/// let spec = SSKRSpec::new(2, vec![group1, group2]).unwrap();
///
/// // Generate the shares
/// let shares = sskr_generate(&spec, &master_secret).unwrap();
///
/// // Verify the structure matches our specification
/// assert_eq!(shares.len(), 2);           // 2 groups
/// assert_eq!(shares[0].len(), 3);        // 3 shares in first group
/// assert_eq!(shares[1].len(), 5);        // 5 shares in second group
/// ```
pub fn sskr_generate(
    spec: &SSKRSpec,
    master_secret: &SSKRSecret,
) -> std::result::Result<Vec<Vec<SSKRShare>>, SSKRError> {
    let mut rng = SecureRandomNumberGenerator;
    sskr_generate_using(spec, master_secret, &mut rng)
}

/// Generates SSKR shares using a custom random number generator.
///
/// This function is similar to `sskr_generate`, but allows specifying a custom
/// random number generator for deterministic testing or other specialized
/// needs.
///
/// # Parameters
///
/// * `spec` - The `SSKRSpec` instance that defines the group threshold, number
///   of groups, and the member thresholds for each group.
/// * `master_secret` - The `SSKRSecret` instance to be split into shares.
/// * `rng` - The random number generator to use for generating shares.
///
/// # Returns
///
/// A result containing a nested vector of `SSKRShare` instances if successful,
/// or an `SSKRError` if the operation fails. The outer vector contains one
/// vector per group, and each inner vector contains the shares for that group.
///
/// # Errors
///
/// Returns an error if:
/// - The secret is too short or too long
/// - The group threshold is invalid
/// - The member thresholds are invalid
/// - Any other error in the underlying SSKR implementation
///
/// # Example
///
/// ```
/// use bc_components::{SSKRSecret, SSKRSpec, SSKRGroupSpec, sskr_generate_using};
/// use bc_rand::SecureRandomNumberGenerator;
///
/// // Create a master secret from a byte array (must be exactly 16 or 32 bytes)
/// let master_secret = SSKRSecret::new(b"0123456789abcdef").unwrap(); // Exactly 16 bytes
///
/// // Configure a split with 2 groups, requiring both groups (threshold = 2)
/// let group1 = SSKRGroupSpec::new(2, 3).unwrap();
/// let group2 = SSKRGroupSpec::new(3, 5).unwrap();
/// let spec = SSKRSpec::new(2, vec![group1, group2]).unwrap();
///
/// // Generate the shares with a custom RNG
/// let mut rng = SecureRandomNumberGenerator;
/// let shares = sskr_generate_using(&spec, &master_secret, &mut rng).unwrap();
///
/// // Verify the structure
/// assert_eq!(shares.len(), 2);
/// assert_eq!(shares[0].len(), 3);
/// assert_eq!(shares[1].len(), 5);
/// ```
pub fn sskr_generate_using(
    spec: &SSKRSpec,
    master_secret: &SSKRSecret,
    rng: &mut impl RandomNumberGenerator,
) -> std::result::Result<Vec<Vec<SSKRShare>>, SSKRError> {
    let shares = sskr::sskr_generate_using(spec, master_secret, rng)?;
    let shares = shares
        .into_iter()
        .map(|group| group.into_iter().map(SSKRShare::from_data).collect())
        .collect();
    Ok(shares)
}

/// Combines SSKR shares to reconstruct the original secret.
///
/// This function takes a collection of shares and attempts to reconstruct the
/// original secret. The shares must meet the group and member thresholds
/// specified when the shares were generated.
///
/// # Parameters
///
/// * `shares` - A slice of `SSKRShare` instances to be combined.
///
/// # Returns
///
/// A result containing the reconstructed `SSKRSecret` if successful,
/// or an `SSKRError` if the shares cannot be combined.
///
/// # Errors
///
/// Returns an error if:
/// - The shares don't all belong to the same split (different identifiers)
/// - There are insufficient shares to meet the group threshold
/// - There are insufficient shares within each group to meet their member
///   thresholds
/// - The shares are malformed or corrupted
///
/// # Example
///
/// ```
/// use bc_components::{SSKRSecret, SSKRSpec, SSKRGroupSpec, SSKRShare, sskr_generate, sskr_combine};
///
/// // Create a master secret (must be exactly 16 or 32 bytes)
/// let master_secret = SSKRSecret::new(b"0123456789abcdef").unwrap(); // Exactly 16 bytes
///
/// // Configure a split with 2 groups, requiring both groups (threshold = 2)
/// let group1 = SSKRGroupSpec::new(2, 3).unwrap();
/// let group2 = SSKRGroupSpec::new(3, 5).unwrap();
/// let spec = SSKRSpec::new(2, vec![group1, group2]).unwrap();
///
/// // Generate the shares
/// let shares = sskr_generate(&spec, &master_secret).unwrap();
///
/// // Collect shares that meet the threshold requirements
/// let recovery_shares = vec![
///     // Two shares from group 1 (meets threshold of 2)
///     shares[0][0].clone(),
///     shares[0][1].clone(),
///
///     // Three shares from group 2 (meets threshold of 3)
///     shares[1][0].clone(),
///     shares[1][1].clone(),
///     shares[1][2].clone(),
/// ];
///
/// // Recover the original secret
/// let recovered_secret = sskr_combine(&recovery_shares).unwrap();
/// assert_eq!(recovered_secret, master_secret);
/// ```
pub fn sskr_combine(shares: &[SSKRShare]) -> std::result::Result<SSKRSecret, SSKRError> {
    let shares: Vec<Vec<u8>> = shares
        .iter()
        .map(|share| share.as_bytes().to_vec())
        .collect();
    sskr::sskr_combine(&shares)
}
