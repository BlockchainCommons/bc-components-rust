use std::sync::Arc;

use bc_tags::*;
#[cfg(feature = "ssh")]
use ssh_key::{
    SshSig as SSHSignature, private::PrivateKey as SSHPrivateKey,
    public::PublicKey as SSHPublicKey,
};

#[cfg(feature = "ssh")]
use crate::ReferenceProvider;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
use crate::SignatureScheme;
use crate::{
    ARID, Digest, EncapsulationScheme, EncryptedKey, Nonce, PrivateKeyBase,
    PrivateKeys, PublicKeys, Reference, SSKRShare, Salt, SealedMessage, Seed,
    Signature, SigningPrivateKey, SigningPublicKey, URI, UUID, XID,
};

pub fn register_tags_in(tags_store: &mut TagsStore) {
    bc_tags::register_tags_in(tags_store);

    tags_store.set_summarizer(
        TAG_DIGEST,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let arid = Digest::from_untagged_cbor(untagged_cbor)?;
            Ok(arid.short_description().flanked_by("Digest(", ")"))
        }),
    );

    tags_store.set_summarizer(
        TAG_ARID,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let arid = ARID::from_untagged_cbor(untagged_cbor)?;
            Ok(arid.short_description().flanked_by("ARID(", ")"))
        }),
    );

    tags_store.set_summarizer(
        TAG_XID,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let xid = XID::from_untagged_cbor(untagged_cbor)?;
            Ok(xid.short_description().flanked_by("XID(", ")"))
        }),
    );

    tags_store.set_summarizer(
        TAG_URI,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let uri = URI::from_untagged_cbor(untagged_cbor)?;
            Ok(uri.to_string().flanked_by("URI(", ")"))
        }),
    );

    tags_store.set_summarizer(
        TAG_UUID,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let uuid = UUID::from_untagged_cbor(untagged_cbor)?;
            Ok(uuid.to_string().flanked_by("UUID(", ")"))
        }),
    );

    tags_store.set_summarizer(
        TAG_NONCE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Nonce::from_untagged_cbor(untagged_cbor)?;
            Ok("Nonce".to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_SALT,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Salt::from_untagged_cbor(untagged_cbor)?;
            Ok("Salt".to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_SEED,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Seed::from_untagged_cbor(untagged_cbor)?;
            Ok("Seed".to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_PRIVATE_KEYS,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(PrivateKeys::from_untagged_cbor(untagged_cbor)?.to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_PUBLIC_KEYS,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(PublicKeys::from_untagged_cbor(untagged_cbor)?.to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_REFERENCE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(Reference::from_untagged_cbor(untagged_cbor)?.to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_ENCRYPTED_KEY,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(EncryptedKey::from_untagged_cbor(untagged_cbor)?.to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_PRIVATE_KEY_BASE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(PrivateKeyBase::from_untagged_cbor(untagged_cbor)?.to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_SIGNING_PRIVATE_KEY,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(SigningPrivateKey::from_untagged_cbor(untagged_cbor)?
                .to_string())
        }),
    );

    tags_store.set_summarizer(
        TAG_SIGNING_PUBLIC_KEY,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            Ok(
                SigningPublicKey::from_untagged_cbor(untagged_cbor)?
                    .to_string(),
            )
        }),
    );

    tags_store.set_summarizer(
        TAG_SIGNATURE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let signature = Signature::from_untagged_cbor(untagged_cbor)?;
            let scheme = signature.scheme();
            let summary = if let Ok(scheme) = scheme {
                #[cfg(any(feature = "secp256k1", feature = "ed25519"))]
                let is_default = scheme == SignatureScheme::default();
                #[cfg(not(any(feature = "secp256k1", feature = "ed25519")))]
                let is_default = false;

                if is_default {
                    "Signature".to_string()
                } else {
                    format!("Signature({scheme:?})")
                }
            } else {
                "Signature(Unknown)".into()
            };
            Ok(summary)
        }),
    );

    tags_store.set_summarizer(
        TAG_SEALED_MESSAGE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let sealed_message =
                SealedMessage::from_untagged_cbor(untagged_cbor)?;
            let encapsulation_scheme = sealed_message.encapsulation_scheme();
            let summary =
                if encapsulation_scheme == EncapsulationScheme::default() {
                    "SealedMessage".to_string()
                } else {
                    format!("SealedMessage({encapsulation_scheme:?})")
                };
            Ok(summary)
        }),
    );

    tags_store.set_summarizer(
        TAG_SSKR_SHARE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            SSKRShare::from_untagged_cbor(untagged_cbor)?;
            Ok("SSKRShare".to_string())
        }),
    );

    #[cfg(feature = "ssh")]
    tags_store.set_summarizer(
        TAG_SSH_TEXT_PRIVATE_KEY,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let ssh_private_key =
                SSHPrivateKey::from_openssh(untagged_cbor.try_into_text()?)
                    .map_err(|e| dcbor::Error::msg(e.to_string()))?;
            Ok(format!(
                "SSHPrivateKey({})",
                ssh_private_key.ref_hex_short()
            ))
        }),
    );

    #[cfg(feature = "ssh")]
    tags_store.set_summarizer(
        TAG_SSH_TEXT_PUBLIC_KEY,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            let ssh_public_key =
                SSHPublicKey::from_openssh(&untagged_cbor.try_into_text()?)
                    .map_err(|e| dcbor::Error::msg(e.to_string()))?;
            Ok(format!("SSHPublicKey({})", ssh_public_key.ref_hex_short()))
        }),
    );

    #[cfg(feature = "ssh")]
    tags_store.set_summarizer(
        TAG_SSH_TEXT_SIGNATURE,
        Arc::new(move |untagged_cbor: CBOR, _flat: bool| {
            SSHSignature::from_pem(untagged_cbor.try_into_text()?)
                .map_err(|e| dcbor::Error::msg(e.to_string()))?;
            Ok("SSHSignature".to_string())
        }),
    );

    #[cfg(feature = "ssh")]
    tags_store.set_summarizer(
        TAG_SSH_TEXT_CERTIFICATE,
        Arc::new(move |_untagged_cbor: CBOR, _flat: bool| {
            // todo: validation
            Ok("SSHCertificate".to_string())
        }),
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
