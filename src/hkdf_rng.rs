use bc_crypto::hash::hkdf_hmac_sha256;
use rand_core::{ CryptoRng, RngCore };
use zeroize::ZeroizeOnDrop;

// This is a random number generator that uses HKDF to generate deterministic
// random numbers. It is a key-stretching mechanism disguised as a random number
// generator. Assuming the key material is robust, this generator is
// cryptographically secure.

#[derive(ZeroizeOnDrop)]
pub struct HKDFRng {
    buffer: Vec<u8>,
    position: usize,
    key_material: Vec<u8>,
    salt: String,
    page_length: usize,
    page_index: usize,
}

impl HKDFRng {
    pub fn new_with_page_length(
        key_material: impl AsRef<[u8]>,
        salt: &str,
        page_length: usize
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

    pub fn new(key_material: impl AsRef<[u8]>, salt: &str) -> Self {
        Self::new_with_page_length(key_material, salt, 32)
    }

    fn fill_buffer(&mut self) {
        let salt_string = format!("{}-{}", self.salt, self.page_index);
        let hkdf = hkdf_hmac_sha256(&self.key_material, salt_string, self.page_length);
        self.buffer = hkdf;
        self.position = 0;
        self.page_index += 1;
    }

    fn next_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut result = Vec::new();
        while result.len() < length {
            if self.position >= self.buffer.len() {
                self.fill_buffer();
            }
            let remaining = length - result.len();
            let available = self.buffer.len() - self.position;
            let take = remaining.min(available);
            result.extend_from_slice(&self.buffer[self.position..self.position + take]);
            self.position += take;
        }
        result
    }
}

impl RngCore for HKDFRng {
    fn next_u32(&mut self) -> u32 {
        let bytes = self.next_bytes(4);
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        let bytes = self.next_bytes(8);
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = self.next_bytes(dest.len());
        dest.copy_from_slice(&bytes);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

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
        assert_eq!(hex::encode(rng.next_bytes(16)), "1032ac8ffea232a27c79fe381d7eb7e4");
        assert_eq!(hex::encode(rng.next_bytes(16)), "aeaaf727d35b6f338218391f9f8fa1f3");
        assert_eq!(hex::encode(rng.next_bytes(16)), "4348a59427711deb1e7d8a6959c6adb4");
        assert_eq!(hex::encode(rng.next_bytes(16)), "5d937a42cb5fb090fe1a1ec88f56e32b");
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
