//! Identifiers for various purposes.
//!
//! This module provides several types of identifiers:
//!
//! - `ARID`: Apparently Random Identifier, a 32-byte cryptographically strong identifier with neutral semantics
//! - `XID`: eXtensible IDentifier, a 32-byte identifier tied to a specific public key at inception
//! - `UUID`: Universally Unique Identifier, a 16-byte identifier with version and variant information
//! - `URI`: Uniform Resource Identifier, a string identifier for resources
//!
//! These identifiers serve different purposes in different contexts:
//!
//! - `ARID` is ideal for creating stable identifiers for mutable data structures without correlations
//! - `XID` is designed for digital identity with extensive verification and delegation capabilities
//! - `UUID` is used for general-purpose identification across systems
//! - `URI` provides a standardized way to reference resources in various protocols

mod arid;
pub use arid::ARID;

mod uri;
pub use uri::URI;

mod uuid;
pub use uuid::UUID;

mod xid;
pub use xid::{XID, XIDProvider};
