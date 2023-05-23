use std::{rc::Rc, borrow::Cow};

use crate::digest::Digest;

pub trait DigestProvider {
    fn digest(&self) -> Cow<Digest>;
}

impl DigestProvider for &[u8] {
    fn digest(&self) -> Cow<Digest> {
        Cow::Owned(Digest::from_image(&self))
    }
}

impl<T> DigestProvider for Rc<T> where T: DigestProvider {
    fn digest(&self) -> Cow<Digest> {
        self.as_ref().digest()
    }
}
