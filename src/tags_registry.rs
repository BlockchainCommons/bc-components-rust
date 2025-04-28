use std::sync::Arc;

use bc_tags::*;

use crate::{
    Digest,
    EncapsulationScheme,
    EncryptedKey,
    Nonce,
    PrivateKeyBase,
    PrivateKeys,
    PublicKeys,
    Reference,
    SSKRShare,
    Salt,
    SealedMessage,
    Seed,
    Signature,
    SignatureScheme,
    ARID,
    URI,
    UUID,
    XID,
};
use ssh_key::{
    private::PrivateKey as SSHPrivateKey,
    public::PublicKey as SSHPublicKey,
    SshSig as SSHSignature,
};

pub fn register_tags_in(tags_store: &mut TagsStore) {
    bc_tags::register_tags_in(tags_store);

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
        TAG_PRIVATE_KEYS,
        Arc::new(move |untagged_cbor: CBOR| {
            let private_keys = PrivateKeys::from_untagged_cbor(untagged_cbor)?;
            Ok(format!("{private_keys}"))
        })
    );

    tags_store.set_summarizer(
        TAG_PUBLIC_KEYS,
        Arc::new(move |untagged_cbor: CBOR| {
            let public_keys = PublicKeys::from_untagged_cbor(untagged_cbor)?;
            Ok(format!("{public_keys}"))
        })
    );

    tags_store.set_summarizer(
        TAG_REFERENCE,
        Arc::new(move |untagged_cbor: CBOR| {
            let reference = Reference::from_untagged_cbor(untagged_cbor)?;
            Ok(format!("{reference}"))
        })
    );

    tags_store.set_summarizer(
        TAG_ENCRYPTED_KEY,
        Arc::new(move |untagged_cbor: CBOR| {
            let encrypted_key = EncryptedKey::from_untagged_cbor(untagged_cbor)?;
            Ok(format!("{encrypted_key}"))
        })
    );

    tags_store.set_summarizer(
        TAG_PRIVATE_KEY_BASE,
        Arc::new(move |untagged_cbor: CBOR| {
            PrivateKeyBase::from_untagged_cbor(untagged_cbor)?;
            Ok("PrivateKeyBase".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SIGNATURE,
        Arc::new(move |untagged_cbor: CBOR| {
            let signature = Signature::from_untagged_cbor(untagged_cbor)?;
            let scheme = signature.scheme();
            let summary = if let Ok(scheme) = scheme {
                if scheme == SignatureScheme::default() {
                    "Signature".to_string()
                } else {
                    format!("Signature({scheme:?})")
                }
            } else {
                "Signature(Unknown)".into()
            };
            Ok(summary)
        })
    );

    tags_store.set_summarizer(
        TAG_SEALED_MESSAGE,
        Arc::new(move |untagged_cbor: CBOR| {
            let sealed_message = SealedMessage::from_untagged_cbor(untagged_cbor)?;
            let encapsulation_scheme = sealed_message.encapsulation_scheme();
            let summary = if encapsulation_scheme == EncapsulationScheme::default() {
                "SealedMessage".to_string()
            } else {
                format!("SealedMessage({encapsulation_scheme:?})")
            };
            Ok(summary)
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
            SSHPrivateKey::from_openssh(untagged_cbor.try_into_text()?).map_err(|e|
                dcbor::Error::from(e.to_string())
            )?;
            Ok("SSHPrivateKey".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSH_TEXT_PUBLIC_KEY,
        Arc::new(move |untagged_cbor: CBOR| {
            SSHPublicKey::from_openssh(&untagged_cbor.try_into_text()?).map_err(|e|
                dcbor::Error::from(e.to_string())
            )?;
            Ok("SSHPublicKey".to_string())
        })
    );

    tags_store.set_summarizer(
        TAG_SSH_TEXT_SIGNATURE,
        Arc::new(move |untagged_cbor: CBOR| {
            SSHSignature::from_pem(untagged_cbor.try_into_text()?).map_err(|e|
                dcbor::Error::from(e.to_string())
            )?;
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
