use crate::digest::Digest;

pub trait DigestProvider {
    fn digest(&self) -> Digest;
}
