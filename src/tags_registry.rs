use std::sync::Arc;

use dcbor::prelude::*;

// Assignments marked "Fixed" are likely to be in active use by external developers.
//
// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
//
// As of August 13 2022, the [IANA registry of CBOR tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml)
// has the following low-numbered values available:
//
// One byte encoding: 6-15, 19-20
// Two byte encoding: 48-51, 53, 55-60, 62, 88-95, 99, 102, 105-109, 113-119, 128-255
//
// Tags in the range 0-23 require "standards action" for the IANA to recognize.
// Tags in the range 24-32767 require a specification to reserve.
// Tags in the range 24-255 only require two bytes to encode.
// Higher numbered tags are first-come, first-served.

// Core Envelope tags.

// A previous version of the Envelope spec used tag #6.24 ("Encoded CBOR Item") as
// the header for the Envelope `leaf` case. Unfortunately, this was not a correct
// use of the tag, as the contents of #6.24 (RFC8949 §3.4.5.1) MUST always be a
// byte string, while we were simply using it as a wrapper/header for any dCBOR
// data item.
//
// https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
//
// The new leaf tag is #6.201, but we will still recognize #6.24 for backwards
// compatibility.

pub use dcbor::TAG_DATE;

use crate::{
    Digest, Nonce, PublicKeyBase, SSKRShare, Salt, SealedMessage, Seed, Signature, ARID, URI, UUID, XID
};
use ssh_key::{
    private::PrivateKey as SSHPrivateKey,
    public::PublicKey as SSHPublicKey,
    SshSig as SSHSignature,
};

pub const TAG_URI: TagValue = 32;
pub const TAG_UUID: TagValue = 37;

pub const TAG_ENCODED_CBOR: TagValue = 24;

pub const TAG_ENVELOPE: TagValue = 200;
pub const TAG_LEAF: TagValue = 201;

// Envelope extension tags
pub const TAG_KNOWN_VALUE: TagValue = 40000;
pub const TAG_DIGEST: TagValue = 40001;
pub const TAG_ENCRYPTED: TagValue = 40002;
pub const TAG_COMPRESSED: TagValue = 40003;

// Tags for subtypes specific to Distributed Function Calls.
pub const TAG_REQUEST: TagValue = 40004;
pub const TAG_RESPONSE: TagValue = 40005;
pub const TAG_FUNCTION: TagValue = 40006;
pub const TAG_PARAMETER: TagValue = 40007;
pub const TAG_PLACEHOLDER: TagValue = 40008;
pub const TAG_REPLACEMENT: TagValue = 40009;
pub const TAG_EVENT: TagValue = 40010;

// These are the utility structures we've identified and speced related to other
// various applications that aren't specifically Bitcoin-related.

pub const TAG_SEED_V1: TagValue = 300; // Fixed
pub const TAG_EC_KEY_V1: TagValue = 306; // Fixed
pub const TAG_SSKR_SHARE_V1: TagValue = 309; // Fixed

pub const TAG_SEED: TagValue = 40300;
pub const TAG_EC_KEY: TagValue = 40306;
pub const TAG_SSKR_SHARE: TagValue = 40309;

pub const TAG_AGREEMENT_PRIVATE_KEY: TagValue = 40010;
pub const TAG_AGREEMENT_PUBLIC_KEY: TagValue = 40011;
pub const TAG_ARID: TagValue = 40012;
pub const TAG_NONCE: TagValue = 40014;
pub const TAG_PASSWORD: TagValue = 40015;
pub const TAG_PRIVATE_KEY_BASE: TagValue = 40016;
pub const TAG_PUBLIC_KEY_BASE: TagValue = 40017;
pub const TAG_SALT: TagValue = 40018;
pub const TAG_SEALED_MESSAGE: TagValue = 40019;
pub const TAG_SIGNATURE: TagValue = 40020;
pub const TAG_SIGNING_PRIVATE_KEY: TagValue = 40021;
pub const TAG_SIGNING_PUBLIC_KEY: TagValue = 40022;
pub const TAG_SYMMETRIC_KEY: TagValue = 40023;
pub const TAG_XID: TagValue = 40024;

// Bitcoin-related

pub const TAG_HDKEY_V1: TagValue = 303; // Fixed
pub const TAG_DERIVATION_PATH_V1: TagValue = 304; // Fixed
pub const TAG_USE_INFO_V1: TagValue = 305; // Fixed
pub const TAG_ADDRESS_V1: TagValue = 307; // Fixed
pub const TAG_OUTPUT_DESCRIPTOR_V1: TagValue = 307; // Fixed
pub const TAG_PSBT_V1: TagValue = 310; // Fixed
pub const TAG_ACCOUNT_V1: TagValue = 311; // Fixed

pub const TAG_HDKEY: TagValue = 40303;
pub const TAG_DERIVATION_PATH: TagValue = 40304;
pub const TAG_USE_INFO: TagValue = 40305;
pub const TAG_ADDRESS: TagValue = 40307;
pub const TAG_OUTPUT_DESCRIPTOR: TagValue = 40308;
pub const TAG_PSBT: TagValue = 40310;
pub const TAG_ACCOUNT_DESCRIPTOR: TagValue = 40311;

pub const TAG_SSH_TEXT_PRIVATE_KEY: TagValue = 40800;
pub const TAG_SSH_TEXT_PUBLIC_KEY: TagValue = 40801;
pub const TAG_SSH_TEXT_SIGNATURE: TagValue = 40802;
pub const TAG_SSH_TEXT_CERTIFICATE: TagValue = 40803;

// Tags for subtypes specific to AccountBundle (crypto-output).
pub const TAG_OUTPUT_SCRIPT_HASH: TagValue = 400; // Fixed
pub const TAG_OUTPUT_WITNESS_SCRIPT_HASH: TagValue = 401; // Fixed
pub const TAG_OUTPUT_PUBLIC_KEY: TagValue = 402; // Fixed
pub const TAG_OUTPUT_PUBLIC_KEY_HASH: TagValue = 403; // Fixed
pub const TAG_OUTPUT_WITNESS_PUBLIC_KEY_HASH: TagValue = 404; // Fixed
pub const TAG_OUTPUT_COMBO: TagValue = 405; // Fixed
pub const TAG_OUTPUT_MULTISIG: TagValue = 406; // Fixed
pub const TAG_OUTPUT_SORTED_MULTISIG: TagValue = 407; // Fixed
pub const TAG_OUTPUT_RAW_SCRIPT: TagValue = 408; // Fixed
pub const TAG_OUTPUT_TAPROOT: TagValue = 409; // Fixed
pub const TAG_OUTPUT_COSIGNER: TagValue = 410; // Fixed

pub fn register_tags_in(tags_store: &mut TagsStore) {
    dcbor::register_tags_in(tags_store);

    let tags = vec![
        (TAG_URI, "url"),
        (TAG_UUID, "uuid"),

        (TAG_ENCODED_CBOR, "encoded-cbor"),

        (TAG_ENVELOPE, "envelope"),
        (TAG_LEAF, "leaf"),

        (TAG_KNOWN_VALUE, "known-value"),
        (TAG_DIGEST, "digest"),
        (TAG_ENCRYPTED, "encrypted"),
        (TAG_COMPRESSED, "compressed"),

        (TAG_REQUEST, "request"),
        (TAG_RESPONSE, "response"),
        (TAG_FUNCTION, "function"),
        (TAG_PARAMETER, "parameter"),
        (TAG_PLACEHOLDER, "placeholder"),
        (TAG_REPLACEMENT, "replacement"),
        (TAG_EVENT, "event"),

        (TAG_SEED_V1, "crypto-seed"),
        (TAG_EC_KEY_V1, "crypto-eckey"),
        (TAG_SSKR_SHARE_V1, "crypto-sskr"),

        (TAG_SEED, "seed"),
        (TAG_EC_KEY, "eckey"),
        (TAG_SSKR_SHARE, "sskr"),

        (TAG_AGREEMENT_PRIVATE_KEY, "agreement-private-key"),
        (TAG_AGREEMENT_PUBLIC_KEY, "agreement-public-key"),
        (TAG_ARID, "arid"),
        (TAG_NONCE, "nonce"),
        (TAG_PASSWORD, "password"),
        (TAG_PRIVATE_KEY_BASE, "crypto-prvkeys"),
        (TAG_PUBLIC_KEY_BASE, "crypto-pubkeys"),
        (TAG_SALT, "salt"),
        (TAG_SEALED_MESSAGE, "crypto-sealed"),
        (TAG_SIGNATURE, "signature"),
        (TAG_SIGNING_PRIVATE_KEY, "signing-private-key"),
        (TAG_SIGNING_PUBLIC_KEY, "signing-public-key"),
        (TAG_SYMMETRIC_KEY, "crypto-key"),
        (TAG_XID, "xid"),

        (TAG_HDKEY_V1, "crypto-hdkey"),
        (TAG_DERIVATION_PATH_V1, "crypto-keypath"),
        (TAG_USE_INFO_V1, "crypto-coin-info"),
        (TAG_ADDRESS_V1, "crypto-address"),
        (TAG_OUTPUT_DESCRIPTOR_V1, "crypto-output"),
        (TAG_PSBT_V1, "crypto-psbt"),
        (TAG_ACCOUNT_V1, "crypto-account"),

        (TAG_HDKEY, "hdkey"),
        (TAG_DERIVATION_PATH, "keypath"),
        (TAG_USE_INFO, "coin-info"),
        (TAG_ADDRESS, "address"),
        (TAG_OUTPUT_DESCRIPTOR, "output-descriptor"),
        (TAG_PSBT, "psbt"),
        (TAG_ACCOUNT_DESCRIPTOR, "account-descriptor"),

        (TAG_SSH_TEXT_PRIVATE_KEY, "ssh-private"),
        (TAG_SSH_TEXT_PUBLIC_KEY, "ssh-public"),
        (TAG_SSH_TEXT_SIGNATURE, "ssh-signature"),
        (TAG_SSH_TEXT_CERTIFICATE, "ssh-certificate"),

        (TAG_OUTPUT_SCRIPT_HASH, "output-script-hash"),
        (TAG_OUTPUT_WITNESS_SCRIPT_HASH, "output-witness-script-hash"),
        (TAG_OUTPUT_PUBLIC_KEY, "output-public-key"),
        (TAG_OUTPUT_PUBLIC_KEY_HASH, "output-public-key-hash"),
        (TAG_OUTPUT_WITNESS_PUBLIC_KEY_HASH, "output-witness-public-key-hash"),
        (TAG_OUTPUT_COMBO, "output-combo"),
        (TAG_OUTPUT_MULTISIG, "output-multisig"),
        (TAG_OUTPUT_SORTED_MULTISIG, "output-sorted-multisig"),
        (TAG_OUTPUT_RAW_SCRIPT, "output-raw-script"),
        (TAG_OUTPUT_TAPROOT, "output-taproot"),
        (TAG_OUTPUT_COSIGNER, "output-cosigner")
    ];
    for tag in tags.into_iter() {
        tags_store.insert(Tag::new(tag.0, tag.1));
    }

    tags_store.set_summarizer(
        TAG_DIGEST,
        Arc::new(move |untagged_cbor: CBOR| {
            let arid = Digest::from_untagged_cbor(untagged_cbor)?;
            Ok(arid.short_description().flanked_by("Digest(", ")"))
        })
    );

    tags_store.set_summarizer(
        TAG_ARID,
        Arc::new(move |untagged_cbor: CBOR| {
            let arid = ARID::from_untagged_cbor(untagged_cbor)?;
            Ok(arid.short_description().flanked_by("ARID(", ")"))
        })
    );

    tags_store.set_summarizer(
        TAG_XID,
        Arc::new(move |untagged_cbor: CBOR| {
            let xid = XID::from_untagged_cbor(untagged_cbor)?;
            Ok(xid.short_description().flanked_by("XID(", ")"))
        })
    );

    tags_store.set_summarizer(
        TAG_URI,
        Arc::new(move |untagged_cbor: CBOR| {
            let uri = URI::from_untagged_cbor(untagged_cbor)?;
            Ok(uri.to_string().flanked_by("URI(", ")"))
        })
    );

    tags_store.set_summarizer(
        TAG_UUID,
        Arc::new(move |untagged_cbor: CBOR| {
            let uuid = UUID::from_untagged_cbor(untagged_cbor)?;
            Ok(uuid.to_string().flanked_by("UUID(", ")"))
        })
    );

    tags_store.set_summarizer(
        TAG_NONCE,
        Arc::new(move |untagged_cbor: CBOR| {
            Nonce::from_untagged_cbor(untagged_cbor)?;
            Ok("Nonce".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SALT,
        Arc::new(move |untagged_cbor: CBOR| {
            Salt::from_untagged_cbor(untagged_cbor)?;
            Ok("Salt".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SEED,
        Arc::new(move |untagged_cbor: CBOR| {
            Seed::from_untagged_cbor(untagged_cbor)?;
            Ok("Seed".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_PUBLIC_KEY_BASE,
        Arc::new(move |untagged_cbor: CBOR| {
            PublicKeyBase::from_untagged_cbor(untagged_cbor)?;
            Ok("PublicKeyBase".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SIGNATURE,
        Arc::new(move |untagged_cbor: CBOR| {
            Signature::from_untagged_cbor(untagged_cbor)?;
            Ok("Signature".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SEALED_MESSAGE,
        Arc::new(move |untagged_cbor: CBOR| {
            SealedMessage::from_untagged_cbor(untagged_cbor)?;
            Ok("SealedMessage".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSKR_SHARE,
        Arc::new(move |untagged_cbor: CBOR| {
            SSKRShare::from_untagged_cbor(untagged_cbor)?;
            Ok("SSKRShare".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSH_TEXT_PRIVATE_KEY,
        Arc::new(move |untagged_cbor: CBOR| {
            SSHPrivateKey::from_openssh(untagged_cbor.try_into_text()?)?;
            Ok("SSHPrivateKey".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSH_TEXT_PUBLIC_KEY,
        Arc::new(move |untagged_cbor: CBOR| {
            SSHPublicKey::from_openssh(&untagged_cbor.try_into_text()?)?;
            Ok("SSHPublicKey".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSH_TEXT_SIGNATURE,
        Arc::new(move |untagged_cbor: CBOR| {
            SSHSignature::from_pem(untagged_cbor.try_into_text()?)?;
            Ok("SSHSignature".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSH_TEXT_CERTIFICATE,
        Arc::new(move |_untagged_cbor: CBOR| {
            // todo: validation
            Ok("SSHCertificate".to_string())
        })
    );
}

pub fn register_tags() {
    with_tags_mut!(|tags_store: &mut TagsStore| {
        register_tags_in(tags_store);
    });
}

trait StringUtils {
    fn flanked_by(&self, left: &str, right: &str) -> String;
}

impl StringUtils for &str {
    fn flanked_by(&self, left: &str, right: &str) -> String {
        format!("{}{}{}", left, self, right)
    }
}

impl StringUtils for String {
    fn flanked_by(&self, left: &str, right: &str) -> String {
        format!("{}{}{}", left, self, right)
    }
}
