use dcbor::Tag;
use paste::paste;
use std::sync::{Once, Mutex};
use dcbor::KnownTagsDict;

// Assignments marked "Fixed" are likely to be in active use by external developers.

// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md

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

// See https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
tag_constant!(LEAF, 24, "leaf");

tag_constant!(ENVELOPE,         200, "envelope");
tag_constant!(ASSERTION,        201, "assertion");
tag_constant!(KNOWN_VALUE,      202, "known-value");
tag_constant!(WRAPPED_ENVELOPE, 203, "wrapped-envelope");
tag_constant!(DIGEST,           204, "digest");
tag_constant!(ENCRYPTED,        205, "encrypted");
tag_constant!(COMPRESSED,       206, "compressed");

// Tags for subtypes specific to Distributed Function Calls. These tags use
// two-byte encoding.

tag_constant!(REQUEST,      207, "request");
tag_constant!(RESPONSE,     208, "response");
tag_constant!(FUNCTION,     209, "function");
tag_constant!(PARAMETER,    210, "parameter");
tag_constant!(PLACEHOLDER,  211, "placeholder");
tag_constant!(REPLACEMENT,  212, "replacement");

// These are the utility structures we've identified and speced related to other
// various applications that aren't specifically Bitcoin-related.

tag_constant!(SEED,                     300, "crypto-seed"); // Fixed
tag_constant!(AGREEMENT_PRIVATE_KEY,    301, "agreement-private-key");
tag_constant!(AGREEMENT_PUBLIC_KEY,     302, "agreement-public-key");
tag_constant!(EC_KEY,                   306, "crypto-eckey"); // Fixed
tag_constant!(SSKR_SHARE,               309, "crypto-sskr"); // Fixed
tag_constant!(CID,                      312, "cid");
tag_constant!(SEED_DIGEST,              313, "seed-digest");
tag_constant!(NONCE,                    314, "nonce");
tag_constant!(PASSWORD,                 315, "password");
tag_constant!(PRIVATE_KEYBASE,          316, "crypto-prvkeys");
tag_constant!(PUBLIC_KEYBASE,           317, "crypto-pubkeys");
tag_constant!(SALT,                     318, "salt");
tag_constant!(SEALED_MESSAGE,           319, "crypto-sealed");
tag_constant!(SIGNATURE,                320, "signature");
tag_constant!(SIGNING_PRIVATE_KEY,      321, "signing-private-key");
tag_constant!(SIGNING_PUBLIC_KEY,       322, "signing-public-key");
tag_constant!(SYMMETRIC_KEY,            323, "crypto-key");

// Bitcoin-related

tag_constant!(HDKEY,            303, "crypto-hdkey"); // Fixed
tag_constant!(DERIVATION_PATH,  304, "crypto-keypath"); // Fixed
tag_constant!(USE_INFO,         305, "crypto-coin-info"); // Fixed
tag_constant!(ADDRESS,          307, "crypto-address"); // Fixed
tag_constant!(PSBT,             310, "crypto-psbt"); // Fixed
tag_constant!(ACCOUNT,          311, "crypto-account"); // Fixed

// Tags for subtypes specific to AccountBundle (crypto-output).

tag_constant!(OUTPUT, 308, "crypto-output"); // Fixed

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

tag_constant!(OUTPUT_DESCRIPTOR_RESPONSE, 500, "output-descriptor-response"); // Fixed

pub struct LazyKnownTags {
    init: Once,
    data: Mutex<Option<KnownTagsDict>>,
}

impl LazyKnownTags {
    pub fn get(&self) -> std::sync::MutexGuard<'_, Option<KnownTagsDict>> {
        self.init.call_once(|| {
            let m = KnownTagsDict::new([
                LEAF,

                ENVELOPE,
                ASSERTION,
                KNOWN_VALUE,
                WRAPPED_ENVELOPE,
                DIGEST,
                ENCRYPTED,
                COMPRESSED,

                REQUEST,
                RESPONSE,
                FUNCTION,
                PARAMETER,
                PLACEHOLDER,
                REPLACEMENT,

                SEED,
                AGREEMENT_PRIVATE_KEY,
                AGREEMENT_PUBLIC_KEY,
                EC_KEY,
                SSKR_SHARE,
                CID,
                SEED_DIGEST,
                NONCE,
                PASSWORD,
                PRIVATE_KEYBASE,
                PUBLIC_KEYBASE,
                SALT,
                SEALED_MESSAGE,
                SIGNATURE,
                SIGNING_PRIVATE_KEY,
                SIGNING_PUBLIC_KEY,
                SYMMETRIC_KEY,

                HDKEY,
                DERIVATION_PATH,
                USE_INFO,
                ADDRESS,
                PSBT,
                ACCOUNT,

                OUTPUT,

                OUTPUT_SCRIPT_HASH,
                OUTPUT_WITNESS_SCRIPT_HASH,
                OUTPUT_PUBLIC_KEY,
                OUTPUT_PUBLIC_KEY_HASH,
                OUTPUT_WITNESS_PUBLIC_KEY_HASH,
                OUTPUT_COMBO,
                OUTPUT_MULTISIG,
                OUTPUT_SORTED_MULTISIG,
                OUTPUT_RAW_SCRIPT,
                OUTPUT_TAPROOT,
                OUTPUT_COSIGNER,

                OUTPUT_DESCRIPTOR_RESPONSE,
            ]);
            *self.data.lock().unwrap() = Some(m);
        });
        self.data.lock().unwrap()
    }
}

pub static KNOWN_TAGS: LazyKnownTags = LazyKnownTags {
    init: Once::new(),
    data: Mutex::new(None),
};

#[cfg(test)]
mod tests {
    use dcbor::KnownTags;
    use crate::tags_registry::KNOWN_TAGS;

    #[test]
    fn test_1() {
        use crate::*;
        assert_eq!(tags_registry::LEAF.value(), 24);
        assert_eq!(tags_registry::LEAF.name().as_ref().unwrap(), Some("leaf").unwrap());
        let binding = KNOWN_TAGS.get();
        let known_tags = binding.as_ref().unwrap();
        assert_eq!(known_tags.name_for_tag(&tags_registry::LEAF), "leaf");
    }
}
