use std::{rc::Rc, borrow::Cow};

use bc_ur::{UREncodable, URDecodable, URCodable};
use dcbor::{CBORTagged, Tag, CBOREncodable, CBOR, CBORDecodable, CBORError, CBORCodable, CBORTaggedEncodable, CBORTaggedDecodable, CBORTaggedCodable};

use crate::{Nonce, Digest, DigestProvider, tags_registry};

/*
```swift
import Foundation
import URKit
import protocol WolfBase.DataProvider
import BCCrypto

/// A secure encrypted message.
///
/// Implemented using the IETF ChaCha20-Poly1305 encryption.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
///
/// To facilitate decoding, it is recommended that the plaintext of an `EncryptedMessage` be
/// tagged CBOR.
public struct EncryptedMessage: CustomStringConvertible, Equatable {
    public let ciphertext: Data
    public let aad: Data // Additional authenticated data (AAD) per RFC8439
    public let nonce: Nonce
    public let auth: Auth

    public init(ciphertext: Data, aad: Data, nonce: Nonce, auth: Auth) {
        self.ciphertext = ciphertext
        self.aad = aad
        self.nonce = nonce
        self.auth = auth
    }

    public var description: String {
        "Message(ciphertext: \(ciphertext.hex), aad: \(aad.hex), nonce: \(nonce), auth: \(auth))"
    }

    public struct Auth: CustomStringConvertible, Equatable, Hashable {
        public let data: Data

        public init?(_ data: Data) {
            guard data.count == 16 else {
                return nil
            }
            self.data = data
        }

        public init?(_ bytes: [UInt8]) {
            self.init(Data(bytes))
        }

        public var bytes: [UInt8] {
            data.bytes
        }

        public var description: String {
            data.hex.flanked("auth(", ")")
        }
    }
}

extension EncryptedMessage {
    public static func sharedKey(agreementPrivateKey: AgreementPrivateKey, agreementPublicKey: AgreementPublicKey) -> SymmetricKey {
        let keyData = Crypto.deriveAgreementSharedKeyX25519(agreementPrivateKey: agreementPrivateKey.data, agreementPublicKey: agreementPublicKey.data)
        return SymmetricKey(keyData)!
    }
}

extension EncryptedMessage {
    public var digest: Digest? {
        try? Digest(taggedCBOR: CBOR(aad))
    }
}

extension EncryptedMessage: URCodable {
    public static let cborTag = Tag.encrypted

    public var untaggedCBOR: CBOR {
        if self.aad.isEmpty {
            return [ciphertext.cbor, nonce.data.cbor, auth.data.cbor]
        } else {
            return [ciphertext.cbor, nonce.data.cbor, auth.data.cbor, aad.cbor]
        }
    }

    public init(untaggedCBOR: CBOR) throws {
        let (ciphertext, aad, nonce, auth) = try Self.decode(cbor: untaggedCBOR)
        self = EncryptedMessage(ciphertext: ciphertext, aad: aad, nonce: nonce, auth: auth)
    }

    public static func decode(cbor: CBOR) throws -> (ciphertext: Data, aad: Data, nonce: Nonce, auth: Auth)
    {
        guard
            case let CBOR.array(elements) = cbor,
            (3...4).contains(elements.count),
            case let CBOR.bytes(ciphertext) = elements[0],
            case let CBOR.bytes(nonceData) = elements[1],
            let nonce = Nonce(nonceData),
            case let CBOR.bytes(authData) = elements[2],
            let auth = Auth(authData)
        else {
            throw CBORError.invalidFormat
        }

        if elements.count == 4 {
            guard
                case let CBOR.bytes(aad) = elements[3],
                !aad.isEmpty
            else {
                throw CBORError.invalidFormat
            }
            return (ciphertext, aad, nonce, auth)
        } else {
            return (ciphertext, Data(), nonce, auth)
        }
    }
}

```
 */

/// A secure encrypted message.
///
/// Implemented using the IETF ChaCha20-Poly1305 encryption.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
///
/// To facilitate decoding, it is recommended that the plaintext of an `EncryptedMessage` be
/// tagged CBOR.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedMessage {
    ciphertext: Vec<u8>,
    aad: Vec<u8>, // Additional authenticated data (AAD) per RFC8439
    nonce: Nonce,
    auth: Auth,
}

impl EncryptedMessage {
    pub fn new(ciphertext: Vec<u8>, aad: Vec<u8>, nonce: Nonce, auth: Auth) -> Self {
        Self {
            ciphertext,
            aad,
            nonce,
            auth,
        }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    pub fn has_digest(&self) -> bool {
        todo!();
    }

    pub fn digest_ref_opt(&self) -> Option<&Digest> {
        todo!();
    }
}

impl DigestProvider for EncryptedMessage {
    fn digest(&self) -> Cow<Digest> {
        todo!();
    }
}

impl CBORTagged for EncryptedMessage {
    const CBOR_TAG: Tag = tags_registry::ENCRYPTED;
}

impl CBOREncodable for EncryptedMessage {
    fn cbor(&self) -> CBOR {
        if self.aad.is_empty() {
            vec![self.ciphertext.cbor(), self.nonce.cbor(), self.auth.cbor()].cbor()
        } else {
            vec![self.ciphertext.cbor(), self.nonce.cbor(), self.auth.cbor(), self.aad.cbor()].cbor()
        }
    }
}

impl CBORDecodable for EncryptedMessage {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORCodable for EncryptedMessage { }

impl CBORTaggedEncodable for EncryptedMessage {
    fn untagged_cbor(&self) -> CBOR {
        todo!()
    }
}

impl CBORTaggedDecodable for EncryptedMessage {
    fn from_untagged_cbor(_cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        todo!()
    }
}

impl std::fmt::Debug for EncryptedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMessage")
            .field("ciphertext", &hex::encode(&self.ciphertext))
            .field("aad", &hex::encode(&self.aad))
            .field("nonce", &self.nonce)
            .field("auth", &self.auth)
            .finish()
    }
}

impl CBORTaggedCodable for EncryptedMessage { }

impl UREncodable for EncryptedMessage { }

impl URDecodable for EncryptedMessage { }

impl URCodable for EncryptedMessage { }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth([u8; Self::AUTH_LENGTH]);

impl Auth {
    pub const AUTH_LENGTH: usize = 16;

    pub fn from_data(data: [u8; Self::AUTH_LENGTH]) -> Self {
        Self(data)
    }

    pub fn from_data_ref<T>(data: &T) -> Option<Self> where T: AsRef<[u8]> {
        let data = data.as_ref();
        if data.len() != Self::AUTH_LENGTH {
            return None;
        }
        let mut arr = [0u8; Self::AUTH_LENGTH];
        arr.copy_from_slice(data.as_ref());
        Some(Self::from_data(arr))
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Auth {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Auth {
    fn from(data: &[u8]) -> Self {
        Self::from_data_ref(&data).unwrap()
    }
}

impl From<Vec<u8>> for Auth {
    fn from(data: Vec<u8>) -> Self {
        Self::from_data_ref(&data).unwrap()
    }
}

impl CBOREncodable for Auth {
    fn cbor(&self) -> CBOR {
        dcbor::Bytes::from_data(self.data()).cbor()
    }
}

impl CBORDecodable for Auth {
    fn from_cbor(cbor: &CBOR) -> Result<Rc<Self>, CBORError> {
        let bytes = dcbor::Bytes::from_cbor(cbor)?;
        let data = bytes.data();
        let instance = Self::from_data_ref(&data).ok_or(CBORError::InvalidFormat)?;
        Ok(Rc::new(instance))
    }
}
