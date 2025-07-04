use bc_crypto::hash::hkdf_hmac_sha256;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

/// A deterministic random number generator based on HKDF-HMAC-SHA256.
///
/// `HKDFRng` uses the HMAC-based Key Derivation Function (HKDF) to generate
/// deterministic random numbers from a combination of key material and salt. It
/// serves as a key-stretching mechanism that can produce an arbitrary amount of
/// random-looking bytes from a single seed.
///
/// Since it produces deterministic output based on the same inputs, it's useful
/// for situations where repeatable randomness is required, such as in testing
/// or when deterministically deriving keys from a master seed.
///
/// Security considerations:
/// - The security of the generator depends on the entropy and secrecy of the
///   key material
/// - The same key material and salt will always produce the same sequence
/// - Use a secure random seed for cryptographic applications
/// - Never reuse the same HKDFRng instance for different purposes
///
/// The implementation automatically handles buffer management, fetching new
/// data using HKDF as needed with an incrementing counter to ensure unique
/// output for each request.
#[derive(ZeroizeOnDrop)]
pub struct HKDFRng {
    /// Internal buffer of generated bytes
    buffer: Vec<u8>,
    /// Current position in the buffer
    position: usize,
    /// Source key material (seed)
    key_material: Vec<u8>,
    /// Salt value to combine with the key material
    salt: String,
    /// Length of each "page" of generated data
    page_length: usize,
    /// Current page index
    page_index: usize,
}

impl HKDFRng {
    /// Creates a new `HKDFRng` with a custom page length.
    ///
    /// # Parameters
    ///
    /// * `key_material` - The seed material to derive random numbers from
    /// * `salt` - A salt value to mix with the key material
    /// * `page_length` - The number of bytes to generate in each HKDF call
    ///
    /// # Returns
    ///
    /// A new `HKDFRng` instance configured with the specified parameters.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::HKDFRng;
    /// use rand_core::RngCore;
    ///
    /// // Create an HKDF-based RNG with a 64-byte page length
    /// let mut rng = HKDFRng::new_with_page_length(
    ///     b"my secure seed",
    ///     "application-context",
    ///     64,
    /// );
    ///
    /// // Generate some random bytes
    /// let random_u32 = rng.next_u32();
    /// ```
    pub fn new_with_page_length(
        key_material: impl AsRef<[u8]>,
        salt: &str,
        page_length: usize,
    ) -> Self {
        Self {
            buffer: Vec::new(),
            position: 0,
            key_material: key_material.as_ref().to_vec(),
            salt: salt.to_string(),
            page_length,
            page_index: 0,
        }
    }

    /// Creates a new `HKDFRng` with the default page length of 32 bytes.
    ///
    /// # Parameters
    ///
    /// * `key_material` - The seed material to derive random numbers from
    /// * `salt` - A salt value to mix with the key material
    ///
    /// # Returns
    ///
    /// A new `HKDFRng` instance configured with the specified key material and
    /// salt.
    ///
    /// # Example
    ///
    /// ```
    /// use bc_components::HKDFRng;
    /// use rand_core::RngCore;
    ///
    /// // Create an HKDF-based RNG
    /// let mut rng = HKDFRng::new(b"my secure seed", "wallet-derivation");
    ///
    /// // Generate two u32 values
    /// let random1 = rng.next_u32();
    /// let random2 = rng.next_u32();
    ///
    /// // The same seed and salt will always produce the same sequence
    /// let mut rng2 = HKDFRng::new(b"my secure seed", "wallet-derivation");
    /// assert_eq!(random1, rng2.next_u32());
    /// assert_eq!(random2, rng2.next_u32());
    /// ```
    pub fn new(key_material: impl AsRef<[u8]>, salt: &str) -> Self {
        Self::new_with_page_length(key_material, salt, 32)
    }

    /// Refills the internal buffer with new deterministic random bytes.
    ///
    /// This method is called automatically when the internal buffer is
    /// exhausted. It uses HKDF-HMAC-SHA256 to generate a new page of random
    /// bytes using the key material, salt, and current page index.
    fn fill_buffer(&mut self) {
        let salt_string = format!("{}-{}", self.salt, self.page_index);
        let hkdf =
            hkdf_hmac_sha256(&self.key_material, salt_string, self.page_length);
        self.buffer = hkdf;
        self.position = 0;
        self.page_index += 1;
    }

    /// Generates the specified number of deterministic random bytes.
    ///
    /// # Parameters
    ///
    /// * `length` - The number of bytes to generate
    ///
    /// # Returns
    ///
    /// A vector containing the requested number of deterministic random bytes.
    fn next_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut result = Vec::new();
        while result.len() < length {
            if self.position >= self.buffer.len() {
                self.fill_buffer();
            }
            let remaining = length - result.len();
            let available = self.buffer.len() - self.position;
            let take = remaining.min(available);
            result.extend_from_slice(
                &self.buffer[self.position..self.position + take],
            );
            self.position += take;
        }
        result
    }
}

/// Implementation of the `RngCore` trait for `HKDFRng`.
///
/// This allows `HKDFRng` to be used with any code that accepts a random
/// number generator implementing the standard Rust traits.
impl RngCore for HKDFRng {
    /// Generates a random `u32` value.
    ///
    /// # Returns
    ///
    /// A deterministic random 32-bit unsigned integer.
    fn next_u32(&mut self) -> u32 {
        let bytes = self.next_bytes(4);
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    /// Generates a random `u64` value.
    ///
    /// # Returns
    ///
    /// A deterministic random 64-bit unsigned integer.
    fn next_u64(&mut self) -> u64 {
        let bytes = self.next_bytes(8);
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    /// Fills the provided buffer with random bytes.
    ///
    /// # Parameters
    ///
    /// * `dest` - The buffer to fill with random bytes
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = self.next_bytes(dest.len());
        dest.copy_from_slice(&bytes);
    }

    /// Attempts to fill the provided buffer with random bytes.
    ///
    /// This implementation never fails, so it simply calls `fill_bytes`.
    ///
    /// # Parameters
    ///
    /// * `dest` - The buffer to fill with random bytes
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` as this implementation cannot fail.
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Implementation of the `CryptoRng` marker trait for `HKDFRng`.
///
/// This marker indicates that `HKDFRng` is suitable for cryptographic use
/// when seeded with appropriately secure key material.
impl CryptoRng for HKDFRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_rng_new() {
        let rng = HKDFRng::new(b"key_material", "salt");
        assert_eq!(rng.key_material, b"key_material".to_vec());
        assert_eq!(rng.salt, "salt");
        assert_eq!(rng.page_length, 32);
        assert_eq!(rng.page_index, 0);
        assert!(rng.buffer.is_empty());
        assert_eq!(rng.position, 0);
    }

    #[test]
    fn test_hkdf_rng_fill_buffer() {
        let mut rng = HKDFRng::new(b"key_material", "salt");
        rng.fill_buffer();
        assert!(!rng.buffer.is_empty()); // Buffer should be filled
        assert_eq!(rng.position, 0); // Position should be reset
        assert_eq!(rng.page_index, 1); // Page index should be incremented
    }

    #[test]
    fn test_hkdf_rng_next_bytes() {
        let mut rng = HKDFRng::new(b"key_material", "salt");
        assert_eq!(
            hex::encode(rng.next_bytes(16)),
            "1032ac8ffea232a27c79fe381d7eb7e4"
        );
        assert_eq!(
            hex::encode(rng.next_bytes(16)),
            "aeaaf727d35b6f338218391f9f8fa1f3"
        );
        assert_eq!(
            hex::encode(rng.next_bytes(16)),
            "4348a59427711deb1e7d8a6959c6adb4"
        );
        assert_eq!(
            hex::encode(rng.next_bytes(16)),
            "5d937a42cb5fb090fe1a1ec88f56e32b"
        );
    }

    #[test]
    fn test_hkdf_rng_next_u32() {
        let mut rng = HKDFRng::new(b"key_material", "salt");
        let num = rng.next_u32();
        assert_eq!(num, 2410426896);
    }

    #[test]
    fn test_hkdf_rng_next_u64() {
        let mut rng = HKDFRng::new(b"key_material", "salt");
        let num = rng.next_u64();
        assert_eq!(num, 11687583197195678224);
    }

    #[test]
    fn test_hkdf_rng_fill_bytes() {
        let mut rng = HKDFRng::new(b"key_material", "salt");
        let mut dest = [0u8; 16];
        rng.fill_bytes(&mut dest);
        assert_eq!(hex::encode(dest), "1032ac8ffea232a27c79fe381d7eb7e4");
    }

    #[test]
    fn test_hkdf_rng_try_fill_bytes() {
        let mut rng = HKDFRng::new(b"key_material", "salt");
        let mut dest = [0u8; 16];
        assert!(rng.try_fill_bytes(&mut dest).is_ok()); // Should succeed without errors
        assert_eq!(hex::encode(dest), "1032ac8ffea232a27c79fe381d7eb7e4");
    }
}
