use std::rc::Rc;

use crate::digest::Digest;

pub trait DigestProvider {
    fn digest(&self) -> Digest;
    fn digest_ref<'a>(&'a self) -> &'a Digest;
}

impl DigestProvider for &[u8] {
    fn digest(&self) -> Digest {
        Digest::from_image(self)
    }

    fn digest_ref(&self) -> &Digest {
        &self.digest()
    }
}

impl<T> DigestProvider for Rc<T> where T: DigestProvider {
    fn digest(&self) -> Digest {
        self.as_ref().digest()
    }

    fn digest_ref<'a>(&'a self) -> &'a Digest {
        self.as_ref().digest_ref()
    }
}
