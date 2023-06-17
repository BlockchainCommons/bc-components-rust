use std::{rc::Rc, borrow::Cow};

use crate::digest::Digest;

/// A type that can provide a single unique digest that characterizes its contents.
pub trait DigestProvider {
    fn digest(&self) -> Cow<'_, Digest>;
}

impl DigestProvider for &[u8] {
    fn digest(&self) -> Cow<'_, Digest> {
        Cow::Owned(Digest::from_image(&self))
    }
}

impl<T> DigestProvider for Rc<T> where T: DigestProvider {
    fn digest(&self) -> Cow<'_, Digest> {
        self.as_ref().digest()
    }
}
