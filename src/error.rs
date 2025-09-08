use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid data size for the specified type.
    #[error("invalid {data_type} size: expected {expected}, got {actual}")]
    InvalidSize {
        data_type: String,
        expected: usize,
        actual: usize,
    },

    /// Invalid data format or content.
    #[error("invalid {data_type}: {reason}")]
    InvalidData { data_type: String, reason: String },

    /// Cryptographic operation failed.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// CBOR encoding or decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] dcbor::Error),

    /// SSKR error.
    #[error("SSKR error: {0}")]
    Sskr(#[from] sskr::SSKRError),

    /// SSH key operation failed.
    #[error("SSH operation failed: {0}")]
    Ssh(String),

    /// URI parsing failed.
    #[error("invalid URI: {0}")]
    Uri(#[from] url::ParseError),

    /// Data compression/decompression failed.
    #[error("compression error: {0}")]
    Compression(String),

    /// Post-quantum cryptography library error.
    #[error("post-quantum cryptography error: {0}")]
    PostQuantum(String),

    /// Signature level mismatch.
    #[error("signature level does not match key level")]
    LevelMismatch,

    /// SSH agent operation failed.
    #[error("SSH agent error: {0}")]
    SshAgent(String),

    /// Hex decoding error.
    #[error("hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// UTF-8 conversion error.
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Environment variable error.
    #[error("environment variable error: {0}")]
    Env(#[from] std::env::VarError),

    /// SSH agent client error.
    #[error("SSH agent client error: {0}")]
    SshAgentClient(String),

    /// General error with custom message.
    #[error("{0}")]
    General(String),
}

impl Error {
    /// Create a general error with a custom message.
    pub fn general(msg: impl Into<String>) -> Self {
        Error::General(msg.into())
    }

    /// Create an invalid size error.
    pub fn invalid_size(
        data_type: impl Into<String>,
        expected: usize,
        actual: usize,
    ) -> Self {
        Error::InvalidSize { data_type: data_type.into(), expected, actual }
    }

    /// Create an invalid data error.
    pub fn invalid_data(
        data_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Error::InvalidData {
            data_type: data_type.into(),
            reason: reason.into(),
        }
    }

    /// Create a crypto error.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    /// Create an SSH error.
    pub fn ssh(msg: impl Into<String>) -> Self {
        Error::Ssh(msg.into())
    }

    /// Create a compression error.
    pub fn compression(msg: impl Into<String>) -> Self {
        Error::Compression(msg.into())
    }

    /// Create a post-quantum cryptography error.
    pub fn post_quantum(msg: impl Into<String>) -> Self {
        Error::PostQuantum(msg.into())
    }

    /// Create an SSH agent error.
    pub fn ssh_agent(msg: impl Into<String>) -> Self {
        Error::SshAgent(msg.into())
    }

    /// Create an SSH agent client error.
    pub fn ssh_agent_client(msg: impl Into<String>) -> Self {
        Error::SshAgentClient(msg.into())
    }
}

// Convert our error to dcbor::Error for CBOR trait implementations
impl From<Error> for dcbor::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Cbor(cbor_err) => cbor_err,
            _ => dcbor::Error::msg(err.to_string()),
        }
    }
}

// Convert SSH agent client errors
impl From<ssh_agent_client_rs::Error> for Error {
    fn from(err: ssh_agent_client_rs::Error) -> Self {
        Error::ssh_agent_client(err.to_string())
    }
}

// Convert SSH key errors
impl From<ssh_key::Error> for Error {
    fn from(err: ssh_key::Error) -> Self {
        Error::ssh(err.to_string())
    }
}

// Convert bc_crypto errors
impl From<bc_crypto::Error> for Error {
    fn from(err: bc_crypto::Error) -> Self {
        Error::crypto(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
