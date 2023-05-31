use bc_crypto::SCHNORR_SIGNATURE_SIZE;

pub enum Signature {
    Schnorr{ data: [u8; SCHNORR_SIGNATURE_SIZE], tag: Vec<u8> },
    ECDSA([u8; bc_crypto::ECDSA_SIGNATURE_SIZE]),
}

impl Signature {
    pub fn schnorr_from_data<D>(data: [u8; SCHNORR_SIGNATURE_SIZE], tag: D) -> Self
    where
        D: Into<Vec<u8>>,
    {
        Self::Schnorr{ data, tag: tag.into() }
    }

    pub fn ecdsa_from_data(data: [u8; bc_crypto::ECDSA_SIGNATURE_SIZE]) -> Self {
        Self::ECDSA(data)
    }
}
