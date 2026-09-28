//! A persistable MLS session.
//!
//! OpenMLS keeps its state in a storage provider. To survive a page reload the
//! browser needs to export that storage, keep it somewhere, and restore it
//! later. This module wraps that: `export_state()` hands out the bytes, and
//! `restore()` takes them back.
//!
//! Those bytes contain private key material. The caller must wrap them with a
//! non-extractable key before writing them anywhere, and must understand what
//! that does and does not buy: at rest the state is inert without the wrapping
//! key, but while the tab is open the material is in WebAssembly memory, where
//! a cross-site scripting bug can reach it. See docs/security/e2ee-readiness.md.

use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use wasm_bindgen::prelude::*;

use crate::CIPHERSUITE;

/// The default provider owns its storage privately, so it cannot be restored
/// from exported bytes. This is the same pair of parts, assembled so it can.
pub struct PersistableProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl Default for PersistableProvider {
    fn default() -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
        }
    }
}

impl OpenMlsProvider for PersistableProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// One device's MLS state: its identity and every group it belongs to.
#[wasm_bindgen]
pub struct MlsSession {
    provider: PersistableProvider,
    signature_public_key: Vec<u8>,
    identity: Vec<u8>,
}

#[wasm_bindgen]
impl MlsSession {
    /// A session with no identity yet. Call `create_identity` next.
    #[wasm_bindgen(constructor)]
    pub fn new() -> MlsSession {
        MlsSession {
            provider: PersistableProvider::default(),
            signature_public_key: Vec::new(),
            identity: Vec::new(),
        }
    }

    /// Rebuild a session from previously exported bytes.
    pub fn restore(state: &[u8], signature_public_key: &[u8], identity: &[u8]) -> Result<MlsSession, JsValue> {
        let storage = decode_storage(state)
            .map_err(|error| JsValue::from_str(&format!("restoring the session failed: {error}")))?;

        Ok(MlsSession {
            provider: PersistableProvider {
                crypto: RustCrypto::default(),
                storage,
            },
            signature_public_key: signature_public_key.to_vec(),
            identity: identity.to_vec(),
        })
    }

    /// The whole session as bytes. Contains private keys: wrap before storing.
    pub fn export_state(&self) -> Result<Vec<u8>, JsValue> {
        encode_storage(self.provider.storage())
            .map_err(|error| JsValue::from_str(&format!("exporting the session failed: {error}")))
    }

    /// Generate this device's signing identity. Returns its public key, which
    /// the server stores and other devices verify against.
    pub fn create_identity(&mut self, identity: &str) -> Result<Vec<u8>, JsValue> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|error| JsValue::from_str(&format!("key generation failed: {error:?}")))?;
        signer
            .store(self.provider.storage())
            .map_err(|error| JsValue::from_str(&format!("storing the key failed: {error:?}")))?;

        self.signature_public_key = signer.public().to_vec();
        self.identity = identity.as_bytes().to_vec();
        Ok(self.signature_public_key.clone())
    }

    /// Publish-ready key package. The server hands each one out exactly once.
    pub fn create_key_package(&mut self) -> Result<Vec<u8>, JsValue> {
        let (credential, signer) = self.credential_and_signer()?;
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &signer, credential)
            .map_err(|error| JsValue::from_str(&format!("key package generation failed: {error:?}")))?;

        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| JsValue::from_str(&format!("serialising the key package failed: {error:?}")))
    }

    /// Start a new group. Returns its identifier.
    pub fn create_group(&mut self) -> Result<Vec<u8>, JsValue> {
        let (credential, signer) = self.credential_and_signer()?;
        let group = MlsGroup::new(
            &self.provider,
            &signer,
            &MlsGroupCreateConfig::default(),
            credential,
        )
        .map_err(|error| JsValue::from_str(&format!("group creation failed: {error:?}")))?;

        Ok(group.group_id().as_slice().to_vec())
    }

    /// Add a member using a key package claimed from the server. Returns the
    /// commit and welcome, both of which travel through the server as opaque
    /// bytes, plus the ratchet tree the joiner needs.
    pub fn add_member(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<JsValue, JsValue> {
        let signer = self.signer()?;
        let mut group = self.load_group(group_id)?;

        let key_package_in = KeyPackageIn::tls_deserialize(&mut &key_package[..])
            .map_err(|error| JsValue::from_str(&format!("reading the key package failed: {error:?}")))?;
        let validated = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| JsValue::from_str(&format!("the key package is not valid: {error:?}")))?;

        let (commit, welcome, _info) = group
            .add_members(&self.provider, &signer, &[validated])
            .map_err(|error| JsValue::from_str(&format!("adding the member failed: {error:?}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|error| JsValue::from_str(&format!("merging the commit failed: {error:?}")))?;

        let result = AddMemberResult {
            commit: commit
                .tls_serialize_detached()
                .map_err(|error| JsValue::from_str(&format!("serialising the commit failed: {error:?}")))?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|error| JsValue::from_str(&format!("serialising the welcome failed: {error:?}")))?,
            ratchet_tree: serialize_ratchet_tree(&group)?,
        };
        serde_wasm_like(&result)
    }

    /// Join a group from a welcome delivered by the server.
    pub fn join_group(&mut self, welcome: &[u8], ratchet_tree: &[u8]) -> Result<Vec<u8>, JsValue> {
        let message = MlsMessageIn::tls_deserialize(&mut &welcome[..])
            .map_err(|error| JsValue::from_str(&format!("reading the welcome failed: {error:?}")))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(JsValue::from_str("that message was not a welcome")),
        };

        let tree = RatchetTreeIn::tls_deserialize(&mut &ratchet_tree[..])
            .map_err(|error| JsValue::from_str(&format!("reading the ratchet tree failed: {error:?}")))?;

        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(tree),
        )
        .map_err(|error| JsValue::from_str(&format!("staging the welcome failed: {error:?}")))?;

        let group = staged
            .into_group(&self.provider)
            .map_err(|error| JsValue::from_str(&format!("joining failed: {error:?}")))?;

        Ok(group.group_id().as_slice().to_vec())
    }

    /// Seal an application message. The bytes are what the server stores.
    pub fn seal(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        let signer = self.signer()?;
        let mut group = self.load_group(group_id)?;
        let message = group
            .create_message(&self.provider, &signer, plaintext)
            .map_err(|error| JsValue::from_str(&format!("sealing failed: {error:?}")))?;

        message
            .tls_serialize_detached()
            .map_err(|error| JsValue::from_str(&format!("serialising the message failed: {error:?}")))
    }

    /// Open a message, or apply a commit. Returns the plaintext for an
    /// application message and an empty vector for group state changes.
    pub fn open(&mut self, group_id: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut group = self.load_group(group_id)?;
        let incoming = MlsMessageIn::tls_deserialize(&mut &sealed[..])
            .map_err(|error| JsValue::from_str(&format!("reading the message failed: {error:?}")))?;
        let protocol: ProtocolMessage = incoming
            .try_into_protocol_message()
            .map_err(|error| JsValue::from_str(&format!("not a protocol message: {error:?}")))?;

        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(|error| JsValue::from_str(&format!("processing failed: {error:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(|error| JsValue::from_str(&format!("merging failed: {error:?}")))?;
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    /// The ratchet tree for a group, which a joiner needs alongside a welcome.
    pub fn ratchet_tree(&self, group_id: &[u8]) -> Result<Vec<u8>, JsValue> {
        let group = self.load_group(group_id)?;
        serialize_ratchet_tree(&group)
    }

    fn credential_and_signer(&self) -> Result<(CredentialWithKey, SignatureKeyPair), JsValue> {
        let signer = self.signer()?;
        let credential = BasicCredential::new(self.identity.clone());
        Ok((
            CredentialWithKey {
                credential: credential.into(),
                signature_key: self.signature_public_key.clone().into(),
            },
            signer,
        ))
    }

    fn signer(&self) -> Result<SignatureKeyPair, JsValue> {
        if self.signature_public_key.is_empty() {
            return Err(JsValue::from_str("this session has no identity yet"));
        }
        SignatureKeyPair::read(
            self.provider.storage(),
            &self.signature_public_key,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| JsValue::from_str("the signing key is missing from this session"))
    }

    fn load_group(&self, group_id: &[u8]) -> Result<MlsGroup, JsValue> {
        let id = GroupId::from_slice(group_id);
        MlsGroup::load(self.provider.storage(), &id)
            .map_err(|error| JsValue::from_str(&format!("loading the group failed: {error:?}")))?
            .ok_or_else(|| JsValue::from_str("no such group in this session"))
    }
}

struct AddMemberResult {
    commit: Vec<u8>,
    welcome: Vec<u8>,
    ratchet_tree: Vec<u8>,
}

fn serialize_ratchet_tree(group: &MlsGroup) -> Result<Vec<u8>, JsValue> {
    group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|error| JsValue::from_str(&format!("serialising the ratchet tree failed: {error:?}")))
}

/// Hand three byte strings back to JavaScript without pulling in a serialisation
/// framework: a plain object with base64 fields is enough and keeps the
/// dependency list short.
fn serde_wasm_like(result: &AddMemberResult) -> Result<JsValue, JsValue> {
    let object = js_sys::Object::new();
    for (key, value) in [
        ("commit", &result.commit),
        ("welcome", &result.welcome),
        ("ratchet_tree", &result.ratchet_tree),
    ] {
        js_sys::Reflect::set(
            &object,
            &JsValue::from_str(key),
            &js_sys::Uint8Array::from(value.as_slice()).into(),
        )?;
    }
    Ok(object.into())
}

/// Serialisation of the storage map.
///
/// OpenMLS's own serialiser for `MemoryStorage` is behind its `test-utils`
/// feature and documented as being for known-answer tests, so it is not
/// something to build persistence on. The `values` map is public, so we encode
/// it here instead: a count, then length-prefixed key/value pairs. No
/// cryptography, just framing.
fn encode_storage(storage: &MemoryStorage) -> Result<Vec<u8>, String> {
    let values = storage
        .values
        .read()
        .map_err(|_| "the session storage lock was poisoned".to_string())?;

    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for (key, value) in values.iter() {
        out.extend_from_slice(&(key.len() as u64).to_be_bytes());
        out.extend_from_slice(&(value.len() as u64).to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn decode_storage(bytes: &[u8]) -> Result<MemoryStorage, String> {
    let read_u64 = |at: usize, bytes: &[u8]| -> Result<u64, String> {
        bytes
            .get(at..at + 8)
            .ok_or_else(|| "the session state is truncated".to_string())
            .map(|slice| {
                let mut buffer = [0u8; 8];
                buffer.copy_from_slice(slice);
                u64::from_be_bytes(buffer)
            })
    };

    let count = read_u64(0, bytes)?;
    let mut cursor = 8usize;
    let storage = MemoryStorage::default();
    {
        let mut values = storage
            .values
            .write()
            .map_err(|_| "the session storage lock was poisoned".to_string())?;

        for _ in 0..count {
            let key_len = read_u64(cursor, bytes)? as usize;
            let value_len = read_u64(cursor + 8, bytes)? as usize;
            cursor += 16;

            let key = bytes
                .get(cursor..cursor + key_len)
                .ok_or_else(|| "the session state is truncated".to_string())?
                .to_vec();
            cursor += key_len;

            let value = bytes
                .get(cursor..cursor + value_len)
                .ok_or_else(|| "the session state is truncated".to_string())?
                .to_vec();
            cursor += value_len;

            values.insert(key, value);
        }
    }
    Ok(storage)
}
