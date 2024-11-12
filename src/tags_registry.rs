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

// pub const TAG_DATE: u64 = 1; // Declared in dcbor

pub const TAG_URI: u64 = 32;
pub const TAG_UUID: u64 = 37;

pub const TAG_ENCODED_CBOR: u64 = 24;

pub const TAG_ENVELOPE: u64 = 200;
pub const TAG_LEAF: u64 = 201;

// Envelope extension tags
pub const TAG_KNOWN_VALUE: u64 = 40000;
pub const TAG_DIGEST: u64 = 40001;
pub const TAG_ENCRYPTED: u64 = 40002;
pub const TAG_COMPRESSED: u64 = 40003;

// Tags for subtypes specific to Distributed Function Calls.
pub const TAG_REQUEST: u64 = 40004;
pub const TAG_RESPONSE: u64 = 40005;
pub const TAG_FUNCTION: u64 = 40006;
pub const TAG_PARAMETER: u64 = 40007;
pub const TAG_PLACEHOLDER: u64 = 40008;
pub const TAG_REPLACEMENT: u64 = 40009;

// These are the utility structures we've identified and speced related to other
// various applications that aren't specifically Bitcoin-related.

pub const TAG_SEED_V1: u64 = 300; // Fixed
pub const TAG_EC_KEY_V1: u64 = 306; // Fixed
pub const TAG_SSKR_SHARE_V1: u64 = 309; // Fixed

pub const TAG_SEED: u64 = 40300;
pub const TAG_EC_KEY: u64 = 40306;
pub const TAG_SSKR_SHARE: u64 = 40309;

pub const TAG_AGREEMENT_PRIVATE_KEY: u64 = 40010;
pub const TAG_AGREEMENT_PUBLIC_KEY: u64 = 40011;
pub const TAG_ARID: u64 = 40012;
pub const TAG_NONCE: u64 = 40014;
pub const TAG_PASSWORD: u64 = 40015;
pub const TAG_PRIVATE_KEY_BASE: u64 = 40016;
pub const TAG_PUBLIC_KEY_BASE: u64 = 40017;
pub const TAG_SALT: u64 = 40018;
pub const TAG_SEALED_MESSAGE: u64 = 40019;
pub const TAG_SIGNATURE: u64 = 40020;
pub const TAG_SIGNING_PRIVATE_KEY: u64 = 40021;
pub const TAG_SIGNING_PUBLIC_KEY: u64 = 40022;
pub const TAG_SYMMETRIC_KEY: u64 = 40023;
pub const TAG_XID: u64 = 40024;

// Bitcoin-related

pub const TAG_HDKEY_V1: u64 = 303; // Fixed
pub const TAG_DERIVATION_PATH_V1: u64 = 304; // Fixed
pub const TAG_USE_INFO_V1: u64 = 305; // Fixed
pub const TAG_ADDRESS_V1: u64 = 307; // Fixed
pub const TAG_OUTPUT_DESCRIPTOR_V1: u64 = 307; // Fixed
pub const TAG_PSBT_V1: u64 = 310; // Fixed
pub const TAG_ACCOUNT_V1: u64 = 311; // Fixed

pub const TAG_HDKEY: u64 = 40303;
pub const TAG_DERIVATION_PATH: u64 = 40304;
pub const TAG_USE_INFO: u64 = 40305;
pub const TAG_ADDRESS: u64 = 40307;
pub const TAG_OUTPUT_DESCRIPTOR: u64 = 40308;
pub const TAG_PSBT: u64 = 40310;
pub const TAG_ACCOUNT_DESCRIPTOR: u64 = 40311;

pub const TAG_SSH_TEXT_PRIVATE_KEY: u64 = 40800;
pub const TAG_SSH_TEXT_PUBLIC_KEY: u64 = 40801;
pub const TAG_SSH_TEXT_SIGNATURE: u64 = 40802;
pub const TAG_SSH_TEXT_CERTIFICATE: u64 = 40803;

// Tags for subtypes specific to AccountBundle (crypto-output).
pub const TAG_OUTPUT_SCRIPT_HASH: u64 = 400; // Fixed
pub const TAG_OUTPUT_WITNESS_SCRIPT_HASH: u64 = 401; // Fixed
pub const TAG_OUTPUT_PUBLIC_KEY: u64 = 402; // Fixed
pub const TAG_OUTPUT_PUBLIC_KEY_HASH: u64 = 403; // Fixed
pub const TAG_OUTPUT_WITNESS_PUBLIC_KEY_HASH: u64 = 404; // Fixed
pub const TAG_OUTPUT_COMBO: u64 = 405; // Fixed
pub const TAG_OUTPUT_MULTISIG: u64 = 406; // Fixed
pub const TAG_OUTPUT_SORTED_MULTISIG: u64 = 407; // Fixed
pub const TAG_OUTPUT_RAW_SCRIPT: u64 = 408; // Fixed
pub const TAG_OUTPUT_TAPROOT: u64 = 409; // Fixed
pub const TAG_OUTPUT_COSIGNER: u64 = 410; // Fixed

pub fn register_tags() {
    dcbor::register_tags();

    let tags = [
        Tag::new_with_name(TAG_URI, "url"),
        Tag::new_with_name(TAG_UUID, "uuid"),

        Tag::new_with_name(TAG_ENCODED_CBOR, "encoded-cbor"),

        Tag::new_with_name(TAG_ENVELOPE, "envelope"),
        Tag::new_with_name(TAG_LEAF, "leaf"),

        Tag::new_with_name(TAG_KNOWN_VALUE, "known-value"),
        Tag::new_with_name(TAG_DIGEST, "digest"),
        Tag::new_with_name(TAG_ENCRYPTED, "encrypted"),
        Tag::new_with_name(TAG_COMPRESSED, "compressed"),

        Tag::new_with_name(TAG_REQUEST, "request"),
        Tag::new_with_name(TAG_RESPONSE, "response"),
        Tag::new_with_name(TAG_FUNCTION, "function"),
        Tag::new_with_name(TAG_PARAMETER, "parameter"),
        Tag::new_with_name(TAG_PLACEHOLDER, "placeholder"),
        Tag::new_with_name(TAG_REPLACEMENT, "replacement"),

        Tag::new_with_name(TAG_SEED_V1, "crypto-seed"),
        Tag::new_with_name(TAG_EC_KEY_V1, "crypto-eckey"),
        Tag::new_with_name(TAG_SSKR_SHARE_V1, "crypto-sskr"),

        Tag::new_with_name(TAG_SEED, "seed"),
        Tag::new_with_name(TAG_EC_KEY, "eckey"),
        Tag::new_with_name(TAG_SSKR_SHARE, "sskr"),

        Tag::new_with_name(TAG_AGREEMENT_PRIVATE_KEY, "agreement-private-key"),
        Tag::new_with_name(TAG_AGREEMENT_PUBLIC_KEY, "agreement-public-key"),
        Tag::new_with_name(TAG_ARID, "arid"),
        Tag::new_with_name(TAG_NONCE, "nonce"),
        Tag::new_with_name(TAG_PASSWORD, "password"),
        Tag::new_with_name(TAG_PRIVATE_KEY_BASE, "crypto-prvkeys"),
        Tag::new_with_name(TAG_PUBLIC_KEY_BASE, "crypto-pubkeys"),
        Tag::new_with_name(TAG_SALT, "salt"),
        Tag::new_with_name(TAG_SEALED_MESSAGE, "crypto-sealed"),
        Tag::new_with_name(TAG_SIGNATURE, "signature"),
        Tag::new_with_name(TAG_SIGNING_PRIVATE_KEY, "signing-private-key"),
        Tag::new_with_name(TAG_SIGNING_PUBLIC_KEY, "signing-public-key"),
        Tag::new_with_name(TAG_SYMMETRIC_KEY, "crypto-key"),
        Tag::new_with_name(TAG_XID, "xid"),

        Tag::new_with_name(TAG_HDKEY_V1, "crypto-hdkey"),
        Tag::new_with_name(TAG_DERIVATION_PATH_V1, "crypto-keypath"),
        Tag::new_with_name(TAG_USE_INFO_V1, "crypto-coin-info"),
        Tag::new_with_name(TAG_ADDRESS_V1, "crypto-address"),
        Tag::new_with_name(TAG_OUTPUT_DESCRIPTOR_V1, "crypto-output"),
        Tag::new_with_name(TAG_PSBT_V1, "crypto-psbt"),
        Tag::new_with_name(TAG_ACCOUNT_V1, "crypto-account"),

        Tag::new_with_name(TAG_HDKEY, "hdkey"),
        Tag::new_with_name(TAG_DERIVATION_PATH, "keypath"),
        Tag::new_with_name(TAG_USE_INFO, "coin-info"),
        Tag::new_with_name(TAG_ADDRESS, "address"),
        Tag::new_with_name(TAG_OUTPUT_DESCRIPTOR, "output-descriptor"),
        Tag::new_with_name(TAG_PSBT, "psbt"),
        Tag::new_with_name(TAG_ACCOUNT_DESCRIPTOR, "account-descriptor"),

        Tag::new_with_name(TAG_SSH_TEXT_PRIVATE_KEY, "ssh-private"),
        Tag::new_with_name(TAG_SSH_TEXT_PUBLIC_KEY, "ssh-public"),
        Tag::new_with_name(TAG_SSH_TEXT_SIGNATURE, "ssh-signature"),
        Tag::new_with_name(TAG_SSH_TEXT_CERTIFICATE, "ssh-certificate"),

        Tag::new_with_name(TAG_OUTPUT_SCRIPT_HASH, "output-script-hash"),
        Tag::new_with_name(TAG_OUTPUT_WITNESS_SCRIPT_HASH, "output-witness-script-hash"),
        Tag::new_with_name(TAG_OUTPUT_PUBLIC_KEY, "output-public-key"),
        Tag::new_with_name(TAG_OUTPUT_PUBLIC_KEY_HASH, "output-public-key-hash"),
        Tag::new_with_name(TAG_OUTPUT_WITNESS_PUBLIC_KEY_HASH, "output-witness-public-key-hash"),
        Tag::new_with_name(TAG_OUTPUT_COMBO, "output-combo"),
        Tag::new_with_name(TAG_OUTPUT_MULTISIG, "output-multisig"),
        Tag::new_with_name(TAG_OUTPUT_SORTED_MULTISIG, "output-sorted-multisig"),
        Tag::new_with_name(TAG_OUTPUT_RAW_SCRIPT, "output-raw-script"),
        Tag::new_with_name(TAG_OUTPUT_TAPROOT, "output-taproot"),
        Tag::new_with_name(TAG_OUTPUT_COSIGNER, "output-cosigner"),
    ];
    with_tags_mut!(|tags_store: &mut TagsStore| {
        for tag in tags.into_iter() {
            tags_store.insert(tag);
        }
    });
}
