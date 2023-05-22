use std::rc::Rc;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth {
    data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedMessage {
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
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

    pub fn has_digest(&self) -> bool {
        todo!();
    }

    pub fn digest_ref(&self) -> &Digest {
        todo!();
    }

    pub fn digest_ref_opt(&self) -> Option<&Digest> {
        todo!();
    }
}

impl DigestProvider for EncryptedMessage {
    fn digest(&self) -> Digest {
        todo!()
    }
}

impl CBORTagged for EncryptedMessage {
    const CBOR_TAG: Tag = tags_registry::ENCRYPTED;
}

impl CBOREncodable for EncryptedMessage {
    fn cbor(&self) -> CBOR {
        if self.aad.is_empty() {
            return vec![self.ciphertext.cbor(), self.nonce.cbor(), self.auth.data.cbor()].cbor();
        } else {
            return vec![self.ciphertext.cbor(), self.nonce.cbor(), self.auth.data.cbor(), self.aad.cbor()].cbor();
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

impl CBORTaggedCodable for EncryptedMessage { }

impl UREncodable for EncryptedMessage { }

impl URDecodable for EncryptedMessage { }

impl URCodable for EncryptedMessage { }
