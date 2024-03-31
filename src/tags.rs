use paste::paste;
use std::sync::{Once, Mutex};
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

/// A macro for statically defining a CBOR tag constant.
#[macro_export]
macro_rules! tag_constant {
    ($const_name:ident, $value:expr, $name:expr) => {
        paste! {
            pub const [<$const_name _VALUE>]: u64 = $value;
        }
        pub const $const_name: Tag = Tag::new_with_static_name($value, $name);
    };
}

tag_constant!(DATE, 1, "date");
tag_constant!(URI, 32, "url");
tag_constant!(UUID, 37, "uuid");

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
tag_constant!(ENCODED_CBOR, 24, "encoded-cbor");

tag_constant!(ENVELOPE,         200, "envelope");
tag_constant!(LEAF,             201, "leaf");

// Envelope extension tags
tag_constant!(KNOWN_VALUE,      40000, "known-value");
tag_constant!(DIGEST,           40001, "digest");
tag_constant!(ENCRYPTED,        40002, "encrypted");
tag_constant!(COMPRESSED,       40003, "compressed");

// Tags for subtypes specific to Distributed Function Calls.
tag_constant!(REQUEST,      40004, "request");
tag_constant!(RESPONSE,     40005, "response");
tag_constant!(FUNCTION,     40006, "function");
tag_constant!(PARAMETER,    40007, "parameter");
tag_constant!(PLACEHOLDER,  40008, "placeholder");
tag_constant!(REPLACEMENT,  40009, "replacement");

// These are the utility structures we've identified and speced related to other
// various applications that aren't specifically Bitcoin-related.

tag_constant!(SEED_V1,                  300, "crypto-seed"); // Fixed
tag_constant!(EC_KEY_V1,                306, "crypto-eckey"); // Fixed
tag_constant!(SSKR_SHARE_V1,            309, "crypto-sskr"); // Fixed

tag_constant!(SEED,                     40300, "seed");
tag_constant!(EC_KEY,                   40306, "eckey");
tag_constant!(SSKR_SHARE,               40309, "sskr");

tag_constant!(AGREEMENT_PRIVATE_KEY,    40010, "agreement-private-key");
tag_constant!(AGREEMENT_PUBLIC_KEY,     40011, "agreement-public-key");
tag_constant!(ARID,                     40012, "arid");
tag_constant!(NONCE,                    40014, "nonce");
tag_constant!(PASSWORD,                 40015, "password");
tag_constant!(PRIVATE_KEY_BASE,         40016, "crypto-prvkeys");
tag_constant!(PUBLIC_KEY_BASE,          40017, "crypto-pubkeys");
tag_constant!(SALT,                     40018, "salt");
tag_constant!(SEALED_MESSAGE,           40019, "crypto-sealed");
tag_constant!(SIGNATURE,                40020, "signature");
tag_constant!(SIGNING_PRIVATE_KEY,      40021, "signing-private-key");
tag_constant!(SIGNING_PUBLIC_KEY,       40022, "signing-public-key");
tag_constant!(SYMMETRIC_KEY,            40023, "crypto-key");

// Bitcoin-related

tag_constant!(HDKEY_V1,             303, "crypto-hdkey"); // Fixed
tag_constant!(DERIVATION_PATH_V1,   304, "crypto-keypath"); // Fixed
tag_constant!(USE_INFO_V1,          305, "crypto-coin-info"); // Fixed
tag_constant!(ADDRESS_V1,           307, "crypto-address"); // Fixed
tag_constant!(OUTPUT_DESCRIPTOR_V1, 307, "crypto-output"); // Fixed
tag_constant!(PSBT_V1,              310, "crypto-psbt"); // Fixed
tag_constant!(ACCOUNT_V1,           311, "crypto-account"); // Fixed

tag_constant!(HDKEY,                40303, "hdkey");
tag_constant!(DERIVATION_PATH,      40304, "keypath");
tag_constant!(USE_INFO,             40305, "coin-info");
tag_constant!(ADDRESS,              40307, "address");
tag_constant!(OUTPUT_DESCRIPTOR,    40308, "output-descriptor");
tag_constant!(PSBT,                 40310, "psbt");
tag_constant!(ACCOUNT_DESCRIPTOR,   40311, "account-descriptor");

// Tags for subtypes specific to AccountBundle (crypto-output).

tag_constant!(OUTPUT_SCRIPT_HASH,               400, "output-script-hash"); // Fixed
tag_constant!(OUTPUT_WITNESS_SCRIPT_HASH,       401, "output-witness-script-hash"); // Fixed
tag_constant!(OUTPUT_PUBLIC_KEY,                402, "output-public-key"); // Fixed
tag_constant!(OUTPUT_PUBLIC_KEY_HASH,           403, "output-public-key-hash"); // Fixed
tag_constant!(OUTPUT_WITNESS_PUBLIC_KEY_HASH,   404, "output-witness-public-key-hash"); // Fixed
tag_constant!(OUTPUT_COMBO,                     405, "output-combo"); // Fixed
tag_constant!(OUTPUT_MULTISIG,                  406, "output-multisig"); // Fixed
tag_constant!(OUTPUT_SORTED_MULTISIG,           407, "output-sorted-multisig"); // Fixed
tag_constant!(OUTPUT_RAW_SCRIPT,                408, "output-raw-script"); // Fixed
tag_constant!(OUTPUT_TAPROOT,                   409, "output-taproot"); // Fixed
tag_constant!(OUTPUT_COSIGNER,                  410, "output-cosigner"); // Fixed

pub struct LazyTagsStore {
    init: Once,
    data: Mutex<Option<TagsStore>>,
}

impl LazyTagsStore {
    pub fn get(&self) -> std::sync::MutexGuard<'_, Option<TagsStore>> {
        self.init.call_once(|| {
            let m = TagsStore::new([
                ACCOUNT_DESCRIPTOR,
                ACCOUNT_V1,
                ADDRESS,
                ADDRESS_V1,
                AGREEMENT_PRIVATE_KEY,
                AGREEMENT_PUBLIC_KEY,
                ARID,
                COMPRESSED,
                DERIVATION_PATH,
                DERIVATION_PATH_V1,
                DIGEST,
                EC_KEY,
                EC_KEY_V1,
                ENCRYPTED,
                ENVELOPE,
                FUNCTION,
                HDKEY,
                HDKEY_V1,
                KNOWN_VALUE,
                LEAF,
                NONCE,
                OUTPUT_COMBO,
                OUTPUT_COSIGNER,
                OUTPUT_DESCRIPTOR,
                OUTPUT_DESCRIPTOR_V1,
                OUTPUT_MULTISIG,
                OUTPUT_PUBLIC_KEY,
                OUTPUT_PUBLIC_KEY_HASH,
                OUTPUT_RAW_SCRIPT,
                OUTPUT_SCRIPT_HASH,
                OUTPUT_SORTED_MULTISIG,
                OUTPUT_TAPROOT,
                OUTPUT_WITNESS_PUBLIC_KEY_HASH,
                OUTPUT_WITNESS_SCRIPT_HASH,
                PARAMETER,
                PASSWORD,
                PLACEHOLDER,
                PRIVATE_KEY_BASE,
                PSBT,
                PSBT_V1,
                PUBLIC_KEY_BASE,
                REPLACEMENT,
                REQUEST,
                RESPONSE,
                SALT,
                SEALED_MESSAGE,
                SEED,
                SEED_V1,
                SIGNATURE,
                SIGNING_PRIVATE_KEY,
                SIGNING_PUBLIC_KEY,
                SSKR_SHARE,
                SSKR_SHARE_V1,
                SYMMETRIC_KEY,
                USE_INFO,
                USE_INFO_V1,
            ]);
            *self.data.lock().unwrap() = Some(m);
        });
        self.data.lock().unwrap()
    }
}

pub static GLOBAL_TAGS: LazyTagsStore = LazyTagsStore {
    init: Once::new(),
    data: Mutex::new(None),
};

/// A macro for accessing the global tags store.
#[macro_export]
macro_rules! with_tags {
    ($action:expr) => {{
        let binding = $crate::GLOBAL_TAGS.get();
        let tags = binding.as_ref().unwrap();
        #[allow(clippy::redundant_closure_call)]
        $action(tags)
    }};
}

#[cfg(test)]
mod tests {
    use crate::with_tags;

    #[test]
    fn test_1() {
        use crate::*;
        assert_eq!(tags::LEAF.value(), 201);
        assert_eq!(tags::LEAF.name().as_ref().unwrap(), "leaf");
        with_tags!(|tags: &dyn dcbor::TagsStoreTrait| {
            assert_eq!(tags.name_for_tag(&tags::LEAF), "leaf");
        });
    }
}
