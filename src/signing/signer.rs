use crate::{Result};

use crate::{Signature, SigningOptions};

/// A trait for types capable of creating digital signatures.
///
/// The `Signer` trait provides methods for signing messages with various
/// cryptographic signature schemes. Implementations of this trait can sign
/// messages using different algorithms according to the specific signer type.
///
/// This trait is implemented by `SigningPrivateKey` for all supported signature
/// schemes.
///
/// # Examples
///
/// ```
/// use bc_components::{SignatureScheme, Signer, Verifier};
///
/// // Create a key pair using the default signature scheme (Schnorr)
/// let (private_key, public_key) = SignatureScheme::default().keypair();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.sign(&message).unwrap();
///
/// // Verify the signature
/// assert!(public_key.verify(&signature, &message));
/// ```
pub trait Signer {
    /// Signs a message with additional options specific to the signature
    /// scheme.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `options` - Optional signing options (algorithm-specific parameters)
    ///
    /// # Returns
    ///
    /// A `Result` containing the digital signature or an error if signing
    /// fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{cell::RefCell, rc::Rc};
    ///
    /// use bc_components::{SignatureScheme, Signer, SigningOptions, Verifier};
    /// use bc_rand::SecureRandomNumberGenerator;
    ///
    /// // Create a key pair
    /// let (private_key, public_key) = SignatureScheme::Schnorr.keypair();
    ///
    /// // Create signing options for a Schnorr signature
    /// let rng = Rc::new(RefCell::new(SecureRandomNumberGenerator));
    /// let options = SigningOptions::Schnorr { rng };
    ///
    /// // Sign a message with options
    /// let message = b"Hello, world!";
    /// let signature = private_key
    ///     .sign_with_options(&message, Some(options))
    ///     .unwrap();
    ///
    /// // Verify the signature
    /// assert!(public_key.verify(&signature, &message));
    /// ```
    fn sign_with_options(
        &self,
        message: &dyn AsRef<[u8]>,
        options: Option<SigningOptions>,
    ) -> Result<Signature>;

    /// Signs a message using default options.
    ///
    /// This is a convenience method that calls `sign_with_options` with `None`
    /// for the options parameter.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A `Result` containing the digital signature or an error if signing
    /// fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::{SignatureScheme, Signer};
    ///
    /// // Create a key pair
    /// let (private_key, _) = SignatureScheme::Ecdsa.keypair();
    ///
    /// // Sign a message
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    /// ```
    fn sign(&self, message: &dyn AsRef<[u8]>) -> Result<Signature> {
        self.sign_with_options(message, None)
    }
}

/// A trait for types capable of verifying digital signatures.
///
/// The `Verifier` trait provides a method to verify that a signature was
/// created by a corresponding signer for a specific message. This trait is
/// implemented by `SigningPublicKey` for all supported signature schemes.
///
/// # Examples
///
/// ```
/// use bc_components::{SignatureScheme, Signer, Verifier};
///
/// // Create a key pair using the ECDSA signature scheme
/// let (private_key, public_key) = SignatureScheme::Ecdsa.keypair();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.sign(&message).unwrap();
///
/// // Verify the signature
/// assert!(public_key.verify(&signature, &message));
///
/// // Verification should fail for a different message
/// assert!(!public_key.verify(&signature, &b"Different message"));
/// ```
pub trait Verifier {
    /// Verifies a signature against a message.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify
    /// * `message` - The message that was allegedly signed
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the message, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::{SignatureScheme, Signer, Verifier};
    ///
    /// // Create a key pair
    /// let (private_key, public_key) = SignatureScheme::Ed25519.keypair();
    ///
    /// // Sign a message
    /// let message = b"Hello, world!";
    /// let signature = private_key.sign(&message).unwrap();
    ///
    /// // Verify the signature with the correct message (should succeed)
    /// assert!(public_key.verify(&signature, &message));
    ///
    /// // Verify the signature with an incorrect message (should fail)
    /// assert!(!public_key.verify(&signature, &b"Tampered message"));
    /// ```
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool;
}
