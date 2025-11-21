use std::rc::Rc;

use crate::digest::Digest;

/// A type that can provide a single unique digest that characterizes its
/// contents.
///
/// This trait is used to define a common interface for objects that can produce
/// a cryptographic digest (hash) of their content. Implementations of this
/// trait use a `Digest` to avoid unnecessary cloning:
/// - If the digest is already owned by the implementor, it can be returned by
///   borrowing
/// - If it doesn't exist yet, it can be created and returned by owning
///
/// # Use Cases
///
/// The `DigestProvider` trait is useful in scenarios where:
///
/// - You need to verify data integrity
/// - You need a unique identifier for an object based on its content
/// - You want to implement content-addressable storage
/// - You need to compare objects by their content rather than identity
///
/// # Examples
///
/// Implementing `DigestProvider` for a custom type:
///
/// ```
/// use std::borrow::Cow;
///
/// use bc_components::{Digest, DigestProvider};
///
/// struct Document {
///     content: Vec<u8>,
///     cached_digest: Option<Digest>,
/// }
///
/// impl Document {
///     fn new(content: Vec<u8>) -> Self {
///         Self { content, cached_digest: None }
///     }
/// }
///
/// impl DigestProvider for Document {
///     fn digest(&self) -> Digest {
///         match &self.cached_digest {
///             Some(digest) => *digest,
///             None => Digest::from_image(&self.content),
///         }
///     }
/// }
///
/// // Create a document and get its digest
/// let doc = Document::new(b"important data".to_vec());
/// let digest = doc.digest();
/// ```
///
/// Using the provided implementation for `&[u8]`:
///
/// ```
/// use std::borrow::Cow;
///
/// use bc_components::{Digest, DigestProvider};
///
/// // The DigestProvider is implemented for &[u8], not for &[u8; N]
/// let data: &[u8] = b"hello world";
/// let digest_cow: Digest = data.digest();
/// ```
pub trait DigestProvider {
    /// Returns a digest that uniquely characterizes the content of the
    /// implementing type.
    fn digest(&self) -> Digest;
}

/// Implements DigestProvider for byte slices, creating a digest from the
/// slice's contents.
impl DigestProvider for &[u8] {
    fn digest(&self) -> Digest { Digest::from_image(self) }
}

/// Implements DigestProvider for Rc-wrapped types that implement
/// DigestProvider, delegating to the inner type's implementation.
impl<T> DigestProvider for Rc<T>
where
    T: DigestProvider,
{
    fn digest(&self) -> Digest { self.as_ref().digest() }
}
