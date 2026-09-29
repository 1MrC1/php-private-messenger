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
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
    /// Digests of every commit this session has applied or produced.
    ///
    /// A review found why an epoch comparison is not enough: two valid commits
    /// can be built from the same epoch, and whoever delivers them chooses the
    /// order. Recognising a retry by "its epoch is behind ours" therefore also
    /// swallowed a *different* commit from that epoch — including a genuine
    /// removal, which left the removed device reading on the branch the client
    /// silently took. Only the exact bytes we already applied are a retry.
    applied_commits: BTreeSet<[u8; 32]>,
    /// Groups where a commit from an abandoned epoch turned up, meaning our
    /// branch and somebody else's have diverged. Sealing into one is refused:
    /// on a fork we do not know who is still a member.
    diverged_groups: BTreeSet<Vec<u8>>,
    /// The epoch at which this device joined each group.
    ///
    /// Needed to tell two different situations apart, which the first attempt at
    /// fork detection did not: a commit from before we were in the group (the
    /// one that admitted us, for instance, which our welcome already accounted
    /// for) is simply not ours to apply, while a commit from an epoch we did
    /// take part in and have since left is a fork.
    join_epochs: BTreeMap<Vec<u8>, u64>,
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
            applied_commits: BTreeSet::new(),
            diverged_groups: BTreeSet::new(),
            join_epochs: BTreeMap::new(),
        }
    }

    /// Rebuild a session from previously exported bytes.
    pub fn restore(state: &[u8], signature_public_key: &[u8], identity: &[u8]) -> Result<MlsSession, JsValue> {
        let decoded = decode_state(state)
            .map_err(|error| JsValue::from_str(&format!("restoring the session failed: {error}")))?;

        Ok(MlsSession {
            provider: PersistableProvider {
                crypto: RustCrypto::default(),
                storage: decoded.storage,
            },
            signature_public_key: signature_public_key.to_vec(),
            identity: identity.to_vec(),
            applied_commits: decoded.applied_commits,
            diverged_groups: decoded.diverged_groups,
            join_epochs: decoded.join_epochs,
        })
    }

    /// The whole session as bytes. Contains private keys: wrap before storing.
    ///
    /// The commit digests and any divergence travel with it: a reload that
    /// forgot them would start calling forks retries again.
    pub fn export_state(&self) -> Result<Vec<u8>, JsValue> {
        encode_state(
            self.provider.storage(),
            &self.applied_commits,
            &self.diverged_groups,
            &self.join_epochs,
        )
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

        let group_id = group.group_id().as_slice().to_vec();
        // We were here from the beginning, so every epoch is one of ours.
        self.join_epochs.insert(group_id.clone(), group.epoch().as_u64());
        Ok(group_id)
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

        let serialized_commit = commit
            .tls_serialize_detached()
            .map_err(|error| JsValue::from_str(&format!("serialising the commit failed: {error:?}")))?;
        // Our own commit will come back from the queue; record it so it is
        // recognised as a retry rather than mistaken for somebody else's fork.
        self.applied_commits.insert(commit_digest(&serialized_commit));

        let result = AddMemberResult {
            commit: serialized_commit,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|error| JsValue::from_str(&format!("serialising the welcome failed: {error:?}")))?,
            ratchet_tree: serialize_ratchet_tree(&group)?,
        };
        serde_wasm_like(&result)
    }

    /// Whether a device is already a member of a group.
    ///
    /// The directory hands out a key package for every live device of an
    /// account, including devices that are already in this conversation. Adding
    /// one twice would give it two leaves, so the caller needs to be able to
    /// ask.
    pub fn has_member(&self, group_id: &[u8], signature_key: &[u8]) -> Result<bool, JsValue> {
        Ok(self
            .load_group(group_id)?
            .members()
            .any(|member| member.signature_key.as_slice() == signature_key))
    }

    /// The signature key inside a key package, so a caller can tell whose it is
    /// before deciding to add it.
    pub fn key_package_signature_key(key_package: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key_package_in = KeyPackageIn::tls_deserialize(&mut &key_package[..])
            .map_err(|error| JsValue::from_str(&format!("reading the key package failed: {error:?}")))?;
        let crypto = RustCrypto::default();
        let validated = key_package_in
            .validate(&crypto, ProtocolVersion::Mls10)
            .map_err(|error| JsValue::from_str(&format!("the key package is not valid: {error:?}")))?;
        Ok(validated.leaf_node().signature_key().as_slice().to_vec())
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

        let group_id = group.group_id().as_slice().to_vec();
        // Everything before this epoch happened without us; the commit that
        // admitted us is not a fork, it is history our welcome already carried.
        self.join_epochs.insert(group_id.clone(), group.epoch().as_u64());
        Ok(group_id)
    }

    /// Seal an application message. The bytes are what the server stores.
    pub fn seal(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        // On a fork we cannot say who is still a member, so we do not encrypt
        // to a membership we are no longer sure of.
        if self.diverged_groups.contains(&group_id.to_vec()) {
            return Err(JsValue::from_str(
                "this conversation has diverged: another member committed from the same epoch, \
                 so it must be rejoined before anything else is sent",
            ));
        }
        let signer = self.signer()?;
        let mut group = self.load_group(group_id)?;
        let message = group
            .create_message(&self.provider, &signer, plaintext)
            .map_err(|error| JsValue::from_str(&format!("sealing failed: {error:?}")))?;

        message
            .tls_serialize_detached()
            .map_err(|error| JsValue::from_str(&format!("serialising the message failed: {error:?}")))
    }

    /// Open an application message and report who MLS says sent it.
    ///
    /// Returns `{ plaintext, sender_key, sender_leaf }`. The sender is the
    /// protocol's answer, not the server's: a review showed that returning only
    /// the bytes threw away MLS's authorship guarantee, so changing one
    /// server-controlled field re-attributed authenticated content to another
    /// account. The caller must compare `sender_key` against the device
    /// directory and refuse a mismatch.
    ///
    /// A handshake that arrives here is applied as before, and reports itself
    /// with an empty plaintext and no sender.
    pub fn open(&mut self, group_id: &[u8], sealed: &[u8]) -> Result<JsValue, JsValue> {
        let mut group = self.load_group(group_id)?;
        let incoming = MlsMessageIn::tls_deserialize(&mut &sealed[..])
            .map_err(|error| JsValue::from_str(&format!("reading the message failed: {error:?}")))?;
        let protocol: ProtocolMessage = incoming
            .try_into_protocol_message()
            .map_err(|error| JsValue::from_str(&format!("not a protocol message: {error:?}")))?;

        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(|error| JsValue::from_str(&format!("processing failed: {error:?}")))?;

        // Resolve the sender to a leaf and its signature key before consuming
        // the message: this is the identity the protocol authenticated.
        let sender_leaf = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        let sender_key = sender_leaf.and_then(|index| {
            group
                .members()
                .find(|member| member.index == index)
                .map(|member| member.signature_key.to_vec())
        });

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                opened_message(message.into_bytes(), sender_key, sender_leaf)
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(|error| JsValue::from_str(&format!("merging failed: {error:?}")))?;
                self.applied_commits.insert(commit_digest(sealed));
                opened_message(Vec::new(), sender_key, sender_leaf)
            }
            _ => opened_message(Vec::new(), sender_key, sender_leaf),
        }
    }

    /// Apply a handshake message — in practice a commit — that another member
    /// produced.
    ///
    /// Without this, a membership change silently desynchronises everyone who
    /// was already in the group: the committer moves to a new epoch and nobody
    /// else does, so the next message cannot be read by anyone. The group id
    /// comes from the message itself, because a client fetching a queue of
    /// handshakes does not necessarily know yet which conversation each one
    /// belongs to.
    ///
    /// Returns what happened rather than throwing for the ordinary cases, so a
    /// caller walking a queue can tell "not mine" from "broken":
    ///
    /// * `applied` — the group moved to the new epoch
    /// * `already-applied` — behind our epoch; our own commit, or a re-fetch
    /// * `unknown-group` — a conversation this device has not joined
    /// * `proposal` / `not-a-handshake` — nothing to apply
    pub fn apply_handshake(&mut self, handshake: &[u8]) -> Result<String, JsValue> {
        let digest = commit_digest(handshake);
        if self.applied_commits.contains(&digest) {
            // The exact bytes we already applied, or our own commit coming back
            // from the queue. This is the only safe meaning of "duplicate".
            return Ok("already-applied".to_string());
        }

        let incoming = MlsMessageIn::tls_deserialize(&mut &handshake[..])
            .map_err(|error| JsValue::from_str(&format!("reading the handshake failed: {error:?}")))?;
        let protocol: ProtocolMessage = incoming
            .try_into_protocol_message()
            .map_err(|error| JsValue::from_str(&format!("not a protocol message: {error:?}")))?;

        let group_id = protocol.group_id().clone();
        let mut group = match MlsGroup::load(self.provider.storage(), &group_id)
            .map_err(|error| JsValue::from_str(&format!("loading the group failed: {error:?}")))?
        {
            Some(group) => group,
            None => return Ok("unknown-group".to_string()),
        };

        if protocol.epoch().as_u64() < group.epoch().as_u64() {
            let joined_at = self
                .join_epochs
                .get(group_id.as_slice())
                .copied()
                .unwrap_or(0);

            if protocol.epoch().as_u64() < joined_at {
                // From before we were in this group — most often the very commit
                // that admitted us, which our welcome already accounted for.
                // Nothing to apply, and nothing wrong.
                return Ok("before-our-time".to_string());
            }

            // A commit we have never applied, from an epoch we did take part in
            // and have since left. Somebody else committed from the same point
            // and the delivery service showed us theirs first. Both commits are
            // valid; they are simply not descendants of one another, and nothing
            // here can tell which branch the rest of the group took.
            //
            // Calling this a duplicate is what let a removed device keep
            // reading. Refuse to send from now on and say so.
            self.diverged_groups.insert(group_id.as_slice().to_vec());
            return Ok("diverged".to_string());
        }

        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(|error| JsValue::from_str(&format!("processing the handshake failed: {error:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(|error| JsValue::from_str(&format!("merging failed: {error:?}")))?;
                self.applied_commits.insert(digest);
                Ok("applied".to_string())
            }
            ProcessedMessageContent::ProposalMessage(_) => Ok("proposal".to_string()),
            ProcessedMessageContent::ApplicationMessage(_) => Ok("not-a-handshake".to_string()),
            _ => Ok("ignored".to_string()),
        }
    }

    /// Whether this session has seen a fork in a group, and so must not send.
    pub fn has_diverged(&self, group_id: &[u8]) -> bool {
        self.diverged_groups.contains(&group_id.to_vec())
    }

    /// The group's current epoch, which every sent envelope has to declare
    /// honestly for the server's rollback check to mean anything.
    pub fn epoch(&self, group_id: &[u8]) -> Result<u64, JsValue> {
        Ok(self.load_group(group_id)?.epoch().as_u64())
    }

    /// This device's own leaf index in the group.
    pub fn own_leaf(&self, group_id: &[u8]) -> Result<u32, JsValue> {
        Ok(self.load_group(group_id)?.own_leaf_index().u32())
    }

    /// The ratchet tree for a group, which a joiner needs alongside a welcome.
    pub fn ratchet_tree(&self, group_id: &[u8]) -> Result<Vec<u8>, JsValue> {
        let group = self.load_group(group_id)?;
        serialize_ratchet_tree(&group)
    }

    /// Remove a member by its signature key and return the commit the others
    /// must apply.
    ///
    /// After this the removed device is on the far side of a new epoch: it can
    /// still read what it received before, which is inherent, but it cannot
    /// read anything sent afterwards.
    pub fn remove_member(&mut self, group_id: &[u8], signature_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let signer = self.signer()?;
        let mut group = self.load_group(group_id)?;

        let leaf = group
            .members()
            .find(|member| member.signature_key.as_slice() == signature_key)
            .map(|member| member.index)
            .ok_or_else(|| JsValue::from_str("that member is not in this group"))?;

        let (commit, _welcome, _info) = group
            .remove_members(&self.provider, &signer, &[leaf])
            .map_err(|error| JsValue::from_str(&format!("removing the member failed: {error:?}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|error| JsValue::from_str(&format!("merging the removal failed: {error:?}")))?;

        let serialized = commit
            .tls_serialize_detached()
            .map_err(|error| JsValue::from_str(&format!("serialising the removal failed: {error:?}")))?;
        self.applied_commits.insert(commit_digest(&serialized));
        Ok(serialized)
    }

    /// This device's own signature key, so a caller can name it for removal.
    pub fn identity_key(&self) -> Vec<u8> {
        self.signature_public_key.clone()
    }

    /// A number two people can read to each other to check they are in the
    /// same conversation with the same keys.
    ///
    /// Derived from every member's signature key, sorted so both sides compute
    /// the same value regardless of who joined first. If the server ever
    /// substitutes a key, this number changes and the people talking can see
    /// that it has. It is a comparison aid, not a protocol guarantee: it only
    /// helps if someone actually compares it out of band.
    pub fn safety_number(&self, group_id: &[u8]) -> Result<String, JsValue> {
        let group = self.load_group(group_id)?;

        let mut keys: Vec<Vec<u8>> = group
            .members()
            .map(|member| member.signature_key.to_vec())
            .collect();
        if keys.is_empty() {
            return Err(JsValue::from_str("that group has no members"));
        }
        keys.sort();

        // The conversation's own secret, not only who is in it.
        //
        // A review found the first version comparing membership alone, so two
        // separately keyed groups with the same people produced the same number
        // — and a welcome cross-routed between them was invisible in it. The
        // exporter secret is specific to this group and this epoch, so it binds
        // both. Every member derives the same value; nobody outside can.
        let exporter = group
            .export_secret(self.provider.crypto(), "pm-safety-number", group_id, 32)
            .map_err(|error| JsValue::from_str(&format!("deriving the safety number failed: {error:?}")))?;

        let mut hasher = Sha256::new();
        hasher.update(b"pm-safety-number-v2");
        hasher.update((group_id.len() as u32).to_be_bytes());
        hasher.update(group_id);
        hasher.update((exporter.len() as u32).to_be_bytes());
        hasher.update(&exporter);
        for key in &keys {
            hasher.update((key.len() as u32).to_be_bytes());
            hasher.update(key);
        }
        let digest = hasher.finalize();

        // Forty digits in eight groups of five, over two lines: the shape
        // people can read aloud without losing their place.
        let mut digits = String::new();
        for (index, chunk) in digest.chunks(4).take(12).enumerate() {
            let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) % 100000;
            if index > 0 && index % 4 == 0 {
                digits.push('\n');
            } else if index > 0 {
                digits.push(' ');
            }
            digits.push_str(&format!("{value:05}"));
        }
        Ok(digits)
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
/// The identity of a commit: the digest of exactly the bytes we were given.
fn commit_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pm-mls-commit-v1");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// `{ plaintext, sender_key, sender_leaf }` for JavaScript. `sender_key` is
/// null for anything MLS did not attribute to a member.
fn opened_message(
    plaintext: Vec<u8>,
    sender_key: Option<Vec<u8>>,
    sender_leaf: Option<LeafNodeIndex>,
) -> Result<JsValue, JsValue> {
    let object = js_sys::Object::new();
    js_sys::Reflect::set(
        &object,
        &JsValue::from_str("plaintext"),
        &js_sys::Uint8Array::from(plaintext.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &object,
        &JsValue::from_str("sender_key"),
        &match &sender_key {
            Some(key) => js_sys::Uint8Array::from(key.as_slice()).into(),
            None => JsValue::NULL,
        },
    )?;
    js_sys::Reflect::set(
        &object,
        &JsValue::from_str("sender_leaf"),
        &match sender_leaf {
            Some(index) => JsValue::from_f64(index.u32() as f64),
            None => JsValue::NULL,
        },
    )?;
    Ok(object.into())
}

/// Everything `restore()` needs: the provider's storage plus the bookkeeping
/// that makes fork detection survive a reload.
struct DecodedState {
    storage: MemoryStorage,
    applied_commits: BTreeSet<[u8; 32]>,
    diverged_groups: BTreeSet<Vec<u8>>,
    join_epochs: BTreeMap<Vec<u8>, u64>,
}

const STATE_MAGIC: &[u8; 16] = b"pm-mls-state-v2\0";
/// Caps, so a malformed blob cannot ask for an allocation it will not fill. The
/// review that found the old parser accepted trailing bytes, duplicate keys and
/// a length that truncated to zero on wasm32 also asked for these.
const MAX_ENTRIES: u32 = 100_000;
const MAX_KEY_BYTES: u32 = 4_096;
const MAX_VALUE_BYTES: u32 = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIGESTS: u32 = 100_000;
const MAX_GROUP_IDS: u32 = 10_000;

fn encode_state(
    storage: &MemoryStorage,
    applied_commits: &BTreeSet<[u8; 32]>,
    diverged_groups: &BTreeSet<Vec<u8>>,
    join_epochs: &BTreeMap<Vec<u8>, u64>,
) -> Result<Vec<u8>, String> {
    let values = storage
        .values
        .read()
        .map_err(|_| "the session storage lock was poisoned".to_string())?;

    let mut out = Vec::new();
    out.extend_from_slice(STATE_MAGIC);
    out.extend_from_slice(&u32::try_from(values.len()).map_err(|_| "too many entries".to_string())?.to_be_bytes());
    for (key, value) in values.iter() {
        out.extend_from_slice(&u32::try_from(key.len()).map_err(|_| "key too long".to_string())?.to_be_bytes());
        out.extend_from_slice(&u32::try_from(value.len()).map_err(|_| "value too long".to_string())?.to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }

    out.extend_from_slice(&u32::try_from(applied_commits.len()).map_err(|_| "too many commits".to_string())?.to_be_bytes());
    for digest in applied_commits {
        out.extend_from_slice(digest);
    }

    out.extend_from_slice(&u32::try_from(diverged_groups.len()).map_err(|_| "too many groups".to_string())?.to_be_bytes());
    for group in diverged_groups {
        out.extend_from_slice(&u32::try_from(group.len()).map_err(|_| "group id too long".to_string())?.to_be_bytes());
        out.extend_from_slice(group);
    }

    out.extend_from_slice(&u32::try_from(join_epochs.len()).map_err(|_| "too many groups".to_string())?.to_be_bytes());
    for (group, epoch) in join_epochs {
        out.extend_from_slice(&u32::try_from(group.len()).map_err(|_| "group id too long".to_string())?.to_be_bytes());
        out.extend_from_slice(group);
        out.extend_from_slice(&epoch.to_be_bytes());
    }
    Ok(out)
}

/// A cursor that refuses to read past the end and cannot wrap.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(length)
            .ok_or_else(|| "the session state declares an impossible length".to_string())?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| "the session state is truncated".to_string())?;
        self.at = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let slice = self.take(4)?;
        let mut buffer = [0u8; 4];
        buffer.copy_from_slice(slice);
        Ok(u32::from_be_bytes(buffer))
    }

    fn at_end(&self) -> bool {
        self.at == self.bytes.len()
    }
}

fn bounded(length: u32, cap: u32, what: &str) -> Result<usize, String> {
    if length > cap {
        return Err(format!("the session state declares an implausible {what}"));
    }
    usize::try_from(length).map_err(|_| format!("the session state declares an unusable {what}"))
}

fn decode_state(bytes: &[u8]) -> Result<DecodedState, String> {
    let mut reader = Reader::new(bytes);
    if reader.take(STATE_MAGIC.len())? != STATE_MAGIC {
        return Err("this is not a session state this version understands".to_string());
    }

    let count = reader.u32()?;
    let entries = bounded(count, MAX_ENTRIES, "entry count")?;
    let storage = MemoryStorage::default();
    {
        let mut values = storage
            .values
            .write()
            .map_err(|_| "the session storage lock was poisoned".to_string())?;

        let mut total = 0usize;
        for _ in 0..entries {
            let key_len = bounded(reader.u32()?, MAX_KEY_BYTES, "key length")?;
            let value_len = bounded(reader.u32()?, MAX_VALUE_BYTES, "value length")?;
            total = total
                .checked_add(key_len)
                .and_then(|sum| sum.checked_add(value_len))
                .ok_or_else(|| "the session state is implausibly large".to_string())?;
            if total > MAX_TOTAL_BYTES {
                return Err("the session state is implausibly large".to_string());
            }
            let key = reader.take(key_len)?.to_vec();
            let value = reader.take(value_len)?.to_vec();
            // Two values for one key is ambiguous, and silently keeping the last
            // one loses state. Refuse instead.
            if values.insert(key, value).is_some() {
                return Err("the session state repeats a key".to_string());
            }
        }
    }

    let mut applied_commits = BTreeSet::new();
    let digests = bounded(reader.u32()?, MAX_DIGESTS, "commit count")?;
    for _ in 0..digests {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(reader.take(32)?);
        applied_commits.insert(digest);
    }

    let mut diverged_groups = BTreeSet::new();
    let groups = bounded(reader.u32()?, MAX_GROUP_IDS, "diverged group count")?;
    for _ in 0..groups {
        let length = bounded(reader.u32()?, MAX_KEY_BYTES, "group id length")?;
        diverged_groups.insert(reader.take(length)?.to_vec());
    }

    let mut join_epochs = BTreeMap::new();
    let joined = bounded(reader.u32()?, MAX_GROUP_IDS, "joined group count")?;
    for _ in 0..joined {
        let length = bounded(reader.u32()?, MAX_KEY_BYTES, "group id length")?;
        let group = reader.take(length)?.to_vec();
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(reader.take(8)?);
        if join_epochs.insert(group, u64::from_be_bytes(epoch)).is_some() {
            return Err("the session state repeats a group".to_string());
        }
    }

    // Trailing bytes mean the blob is not what it says it is.
    if !reader.at_end() {
        return Err("the session state has trailing bytes".to_string());
    }

    Ok(DecodedState {
        storage,
        applied_commits,
        diverged_groups,
        join_epochs,
    })
}

