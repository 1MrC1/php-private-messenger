//! Thin WebAssembly wrapper around OpenMLS.
//!
//! Every cryptographic operation here is performed by OpenMLS (pinned to an
//! exact version, MIT licensed, independently audited by SRLabs with the fixes
//! shipped in 0.8.1). This crate exists only to expose a small surface to the
//! browser. If you find yourself implementing a cryptographic primitive in this
//! file, stop: that is precisely what docs/security/e2ee-readiness.md forbids.
//!
//! What exists today is the engine and a proof that it runs. The stateful group
//! management a messenger needs — persisting state, mapping members to devices,
//! recovering keys — is later work, and nothing here entitles anyone to call the
//! application end-to-end encrypted.

use openmls::prelude::*;
// Serialisation traits must be in scope for tls_serialize_detached /
// tls_deserialize on the message types.
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use wasm_bindgen::prelude::*;

/// The one cipher suite this build supports. Pinned rather than negotiated:
/// a downgrade dance is a place bugs hide, and one suite is enough until there
/// is a reason for a second.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[wasm_bindgen]
pub fn version() -> String {
    format!("pm-mls {} / openmls 0.9.0", env!("CARGO_PKG_VERSION"))
}

/// The cipher suite identifier, so the caller can record what sealed a message.
#[wasm_bindgen]
pub fn ciphersuite() -> u16 {
    CIPHERSUITE as u16
}

fn identity(
    name: &str,
    provider: &impl OpenMlsProvider,
) -> Result<(CredentialWithKey, SignatureKeyPair), String> {
    let credential = BasicCredential::new(name.as_bytes().to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|error| format!("signature key generation failed: {error:?}"))?;
    signer
        .store(provider.storage())
        .map_err(|error| format!("storing the signature key failed: {error:?}"))?;

    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    ))
}

/// Run a complete two-party exchange inside the module and return what the
/// second party decrypted.
///
/// This is the honest test of whether MLS works in this environment: it creates
/// two identities, publishes a key package, forms a group, adds the second
/// party, delivers the welcome, seals an application message and opens it. If
/// the returned string matches the input, the audited implementation is
/// functioning in the browser. If any step fails, the error says which.
#[wasm_bindgen]
pub fn self_test(plaintext: &str) -> Result<String, JsValue> {
    round_trip(plaintext).map_err(|error| JsValue::from_str(&error))
}

fn round_trip(plaintext: &str) -> Result<String, String> {
    // Separate providers: each party keeps its own key material, exactly as two
    // browsers would.
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let (alice_credential, alice_signer) = identity("alice", &alice_provider)?;
    let (bob_credential, bob_signer) = identity("bob", &bob_provider)?;

    // Bob publishes a key package; in the real system this is what the server
    // stores and hands out exactly once.
    let bob_key_package = KeyPackage::builder()
        .build(CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
        .map_err(|error| format!("key package generation failed: {error:?}"))?;

    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        alice_credential,
    )
    .map_err(|error| format!("group creation failed: {error:?}"))?;

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .map_err(|error| format!("adding a member failed: {error:?}"))?;

    alice_group
        .merge_pending_commit(&alice_provider)
        .map_err(|error| format!("merging the commit failed: {error:?}"))?;

    // The welcome travels through the server as opaque bytes.
    let serialized_welcome = welcome
        .tls_serialize_detached()
        .map_err(|error| format!("serialising the welcome failed: {error:?}"))?;

    let welcome_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
        .map_err(|error| format!("deserialising the welcome failed: {error:?}"))?;
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err("the welcome was not a welcome message".into()),
    };

    let staged = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .map_err(|error| format!("staging the welcome failed: {error:?}"))?;

    let mut bob_group = staged
        .into_group(&bob_provider)
        .map_err(|error| format!("joining the group failed: {error:?}"))?;

    // Alice seals an application message.
    let sealed = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext.as_bytes())
        .map_err(|error| format!("sealing the message failed: {error:?}"))?;
    let sealed_bytes = sealed
        .tls_serialize_detached()
        .map_err(|error| format!("serialising the message failed: {error:?}"))?;

    // Bob opens it.
    let incoming = MlsMessageIn::tls_deserialize(&mut sealed_bytes.as_slice())
        .map_err(|error| format!("deserialising the message failed: {error:?}"))?;
    let protocol_message: ProtocolMessage = incoming
        .try_into_protocol_message()
        .map_err(|error| format!("not a protocol message: {error:?}"))?;

    let processed = bob_group
        .process_message(&bob_provider, protocol_message)
        .map_err(|error| format!("processing the message failed: {error:?}"))?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            String::from_utf8(message.into_bytes())
                .map_err(|error| format!("the opened message was not text: {error:?}"))
        }
        _ => Err("the opened message was not an application message".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_survives_the_round_trip() {
        let secret = "the studio is free from six";
        assert_eq!(round_trip(secret).expect("round trip failed"), secret);
    }

    #[test]
    fn the_ciphersuite_is_the_one_we_pinned() {
        assert_eq!(ciphersuite(), 1);
    }
}
