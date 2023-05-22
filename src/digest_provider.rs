use crate::digest::Digest;

pub trait DigestProvider {
    fn digest(&self) -> Digest;
}

impl DigestProvider for &[u8] {
    fn digest(&self) -> Digest {
        Digest::from_image(self)
    }
}
