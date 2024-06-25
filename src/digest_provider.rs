use std::{ rc::Rc, borrow::Cow };

use crate::digest::Digest;

/// A type that can provide a single unique digest that characterizes its contents.
///
/// Returns a Cow<'_, Digest> to avoid unnecessary cloning. If the Digest is already
/// owned by the implementor, it can be returned by borrowing. If it doesn't
/// exist yet, it can be created and returned by owning.
pub trait DigestProvider {
    fn digest(&self) -> Cow<'_, Digest>;
}

impl DigestProvider for &[u8] {
    fn digest(&self) -> Cow<'_, Digest> {
        Cow::Owned(Digest::from_image(self))
    }
}

impl<T> DigestProvider for Rc<T> where T: DigestProvider {
    fn digest(&self) -> Cow<'_, Digest> {
        self.as_ref().digest()
    }
}
