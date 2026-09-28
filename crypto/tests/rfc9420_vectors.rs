//! Official RFC 9420 known-answer tests.
//!
//! The vectors in `test-vectors/` are the MLS working group's own, taken
//! verbatim from `mlswg/mls-implementations` (see `test-vectors/PROVENANCE.md`
//! for the commit and checksums). They are run here against the exact library
//! version and cryptographic provider this crate compiles into WebAssembly, so
//! a dependency bump that changes an answer fails the build rather than
//! shipping.
//!
//! WHAT THIS DEMONSTRATES, PRECISELY:
//!
//! * `tree-math` and `key-schedule` are run by **OpenMLS's own KAT runners**,
//!   reached through its `test-utils` feature. The key schedule is the deepest
//!   of the three: it drives the library's real epoch derivation — joiner,
//!   welcome, sender-data, encryption, exporter, authenticator, external,
//!   confirmation, membership and resumption secrets — across every epoch in
//!   the vector and compares each against the published answer.
//! * `crypto-basics` is run here, because the labelled KDF and HPKE helpers are
//!   `pub(crate)` in OpenMLS. `RefHash` and `SignWithLabel` still go through the
//!   library's own code (`HashReference`, `Signable`/`Verifiable`); the
//!   `KDFLabel` and `EncryptContext` encodings are written out from RFC 9420
//!   §5.3 and §8 and checked against the vectors, which is what makes them
//!   worth having.
//!
//! WHAT IT DOES NOT DEMONSTRATE: full protocol conformance. The message
//! protection, welcome, treekem, transcript and passive-client vectors need
//! OpenMLS internals that are not reachable from a dependent crate at all, so
//! they are not run, and this test is not a substitute for the independent
//! review that `docs/security/e2ee-readiness.md` still requires.
//!
//! The `SignWithLabel` harness below is adapted from OpenMLS's own
//! `kat_crypto_basics` (MIT), whose module is `#[cfg(test)]` and therefore not
//! callable from here.

use openmls::prelude::{Ciphersuite, OpenMlsSignaturePublicKey, Signature};
use openmls::prelude_test::{
    hash_ref::HashReference,
    kat_treemath,
    key_schedule::{self, KeyScheduleTestVector},
    signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{HpkeCiphertext, HpkeConfig},
    OpenMlsProvider,
};
use serde::Deserialize;

/// The suite this project pins. A vector run must actually cover it; a run that
/// skipped everything as unsupported would otherwise pass in silence.
const PINNED: u16 = 0x0001;

fn vectors(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd-length hex in a vector");
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).expect("non-hex digit in a vector"))
        .collect()
}

/// `opaque x<V>` from RFC 8446 §3.4 as MLS uses it: a QUIC-style variable
/// length prefix, then the bytes.
fn variable_length(bytes: &[u8]) -> Vec<u8> {
    let length = bytes.len();
    let mut out = if length < 0x40 {
        vec![length as u8]
    } else if length < 0x4000 {
        vec![0x40 | (length >> 8) as u8, (length & 0xff) as u8]
    } else {
        panic!("no vector in these files needs a four-byte length prefix");
    };
    out.extend_from_slice(bytes);
    out
}

/// RFC 9420 §8: `struct { uint16 length; opaque label<V>; opaque context<V>; }`
fn kdf_label(label: &str, context: &[u8], length: u16) -> Vec<u8> {
    let mut out = length.to_be_bytes().to_vec();
    out.extend(variable_length(format!("MLS 1.0 {label}").as_bytes()));
    out.extend(variable_length(context));
    out
}

/// RFC 9420 §5.3: `struct { opaque label<V>; opaque context<V>; }`
fn encrypt_context(label: &str, context: &[u8]) -> Vec<u8> {
    let mut out = variable_length(format!("MLS 1.0 {label}").as_bytes());
    out.extend(variable_length(context));
    out
}

// ---- crypto-basics ---------------------------------------------------------

#[derive(Deserialize)]
struct RefHashCase {
    label: String,
    value: String,
    out: String,
}

#[derive(Deserialize)]
struct ExpandCase {
    secret: String,
    label: String,
    context: String,
    length: u16,
    out: String,
}

#[derive(Deserialize)]
struct DeriveSecretCase {
    secret: String,
    label: String,
    out: String,
}

#[derive(Deserialize)]
struct DeriveTreeSecretCase {
    secret: String,
    label: String,
    generation: u32,
    length: u16,
    out: String,
}

#[derive(Deserialize)]
struct SignCase {
    r#priv: String,
    r#pub: String,
    content: String,
    label: String,
    signature: String,
}

#[derive(Deserialize)]
struct EncryptCase {
    r#priv: String,
    r#pub: String,
    label: String,
    context: String,
    plaintext: String,
    kem_output: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct CryptoBasicsCase {
    cipher_suite: u16,
    ref_hash: RefHashCase,
    expand_with_label: ExpandCase,
    derive_secret: DeriveSecretCase,
    derive_tree_secret: DeriveTreeSecretCase,
    sign_with_label: SignCase,
    encrypt_with_label: EncryptCase,
}

/// The payload OpenMLS's signing code expects: it prefixes the label itself,
/// so the label encoding under test here is the library's, not ours.
#[derive(Clone)]
struct LabelledContent {
    content: Vec<u8>,
    label: String,
    signature: Signature,
}

struct OpaqueSignature(Signature);

impl SignedStruct<LabelledContent> for OpaqueSignature {
    fn from_payload(_: LabelledContent, signature: Signature, _: Vec<u8>) -> Self {
        Self(signature)
    }
}

impl Signable for LabelledContent {
    type SignedOutput = OpaqueSignature;

    fn unsigned_payload(&self) -> Result<Vec<u8>, openmls::prelude::Error> {
        Ok(self.content.clone())
    }

    fn label(&self) -> &str {
        &self.label
    }
}

/// `Verifiable` insists on a type for what a verified value becomes; nothing is
/// carried out of a known-answer test, so this stands in for it.
struct Verified;

impl VerifiedStruct for Verified {}

impl Verifiable for LabelledContent {
    type VerifiedStruct = Verified;

    fn unsigned_payload(&self) -> Result<Vec<u8>, openmls::prelude::Error> {
        Ok(self.content.clone())
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn verify(
        self,
        crypto: &impl OpenMlsCrypto,
        pk: &OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, openmls::prelude::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(Verified)
    }
}

#[test]
fn crypto_basics_vectors_match() {
    let provider = OpenMlsRustCrypto::default();
    let cases: Vec<CryptoBasicsCase> =
        serde_json::from_str(&vectors("crypto-basics.json")).expect("crypto-basics.json parses");
    assert!(!cases.is_empty(), "the vector file is not empty");

    let mut ran = 0;
    let mut covered_pinned = false;

    for case in cases {
        let ciphersuite =
            Ciphersuite::try_from(case.cipher_suite).expect("the vector names a real ciphersuite");
        if !provider
            .crypto()
            .supported_ciphersuites()
            .contains(&ciphersuite)
        {
            continue;
        }
        ran += 1;
        covered_pinned |= case.cipher_suite == PINNED;

        // RefHash, through the library's own hash reference.
        let reference = HashReference::new(
            &unhex(&case.ref_hash.value),
            ciphersuite,
            provider.crypto(),
            case.ref_hash.label.as_bytes(),
        )
        .expect("hashing a reference works");
        assert_eq!(
            unhex(&case.ref_hash.out),
            reference.as_slice(),
            "RefHash for ciphersuite {:#06x}",
            case.cipher_suite
        );

        // ExpandWithLabel.
        let expanded = provider
            .crypto()
            .hkdf_expand(
                ciphersuite.hash_algorithm(),
                &unhex(&case.expand_with_label.secret),
                &kdf_label(
                    &case.expand_with_label.label,
                    &unhex(&case.expand_with_label.context),
                    case.expand_with_label.length,
                ),
                case.expand_with_label.length as usize,
            )
            .expect("HKDF expand works");
        assert_eq!(
            unhex(&case.expand_with_label.out),
            expanded.as_slice(),
            "ExpandWithLabel for ciphersuite {:#06x}",
            case.cipher_suite
        );

        // DeriveSecret: ExpandWithLabel with an empty context and the hash length.
        let hash_length = ciphersuite.hash_length() as u16;
        let derived = provider
            .crypto()
            .hkdf_expand(
                ciphersuite.hash_algorithm(),
                &unhex(&case.derive_secret.secret),
                &kdf_label(&case.derive_secret.label, &[], hash_length),
                hash_length as usize,
            )
            .expect("HKDF expand works");
        assert_eq!(
            unhex(&case.derive_secret.out),
            derived.as_slice(),
            "DeriveSecret for ciphersuite {:#06x}",
            case.cipher_suite
        );

        // DeriveTreeSecret: the generation is the context, big-endian.
        let tree_secret = provider
            .crypto()
            .hkdf_expand(
                ciphersuite.hash_algorithm(),
                &unhex(&case.derive_tree_secret.secret),
                &kdf_label(
                    &case.derive_tree_secret.label,
                    &case.derive_tree_secret.generation.to_be_bytes(),
                    case.derive_tree_secret.length,
                ),
                case.derive_tree_secret.length as usize,
            )
            .expect("HKDF expand works");
        assert_eq!(
            unhex(&case.derive_tree_secret.out),
            tree_secret.as_slice(),
            "DeriveTreeSecret for ciphersuite {:#06x}",
            case.cipher_suite
        );

        // SignWithLabel: the published signature must verify, and so must one
        // we produce ourselves over the same content.
        let public = unhex(&case.sign_with_label.r#pub);
        let key = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            unhex(&case.sign_with_label.r#priv),
            public.clone(),
        );
        let verification_key =
            OpenMlsSignaturePublicKey::new(public.into(), ciphersuite.signature_algorithm())
                .expect("the vector's public key is well formed");
        let published = LabelledContent {
            content: unhex(&case.sign_with_label.content),
            label: case.sign_with_label.label.clone(),
            signature: unhex(&case.sign_with_label.signature).into(),
        };
        published
            .clone()
            .verify(provider.crypto(), &verification_key)
            .expect("the published signature verifies");

        let ours = published.clone().sign(&key).expect("signing works");
        let mine = LabelledContent {
            signature: ours.0,
            ..published.clone()
        };
        mine.verify(provider.crypto(), &verification_key)
            .expect("our own signature over the same content verifies");

        // A wrong label must not verify: the label is load-bearing, not decoration.
        let mislabelled = LabelledContent {
            label: format!("{}X", case.sign_with_label.label),
            ..published.clone()
        };
        assert!(
            mislabelled
                .verify(provider.crypto(), &verification_key)
                .is_err(),
            "a signature must not verify under a different label"
        );

        // EncryptWithLabel: open the published ciphertext, then round-trip our own.
        // `HpkeConfig` is not `Copy`, and each call takes it by value.
        let config = || {
            HpkeConfig(
                ciphersuite.hpke_kem_algorithm(),
                ciphersuite.hpke_kdf_algorithm(),
                ciphersuite.hpke_aead_algorithm(),
            )
        };
        let info = encrypt_context(
            &case.encrypt_with_label.label,
            &unhex(&case.encrypt_with_label.context),
        );
        let published_ciphertext = HpkeCiphertext {
            kem_output: unhex(&case.encrypt_with_label.kem_output).into(),
            ciphertext: unhex(&case.encrypt_with_label.ciphertext).into(),
        };
        let opened = provider
            .crypto()
            .hpke_open(
                config(),
                &published_ciphertext,
                &unhex(&case.encrypt_with_label.r#priv),
                &info,
                &[],
            )
            .expect("the published ciphertext opens");
        assert_eq!(
            unhex(&case.encrypt_with_label.plaintext),
            opened,
            "DecryptWithLabel for ciphersuite {:#06x}",
            case.cipher_suite
        );

        let resealed = provider
            .crypto()
            .hpke_seal(
                config(),
                &unhex(&case.encrypt_with_label.r#pub),
                &info,
                &[],
                &unhex(&case.encrypt_with_label.plaintext),
            )
            .expect("sealing works");
        let reopened = provider
            .crypto()
            .hpke_open(
                config(),
                &resealed,
                &unhex(&case.encrypt_with_label.r#priv),
                &info,
                &[],
            )
            .expect("what we sealed opens again");
        assert_eq!(
            unhex(&case.encrypt_with_label.plaintext),
            reopened,
            "EncryptWithLabel round trip for ciphersuite {:#06x}",
            case.cipher_suite
        );

        // The context is authenticated: opening under a different one must fail.
        assert!(
            provider
                .crypto()
                .hpke_open(
                    config(),
                    &published_ciphertext,
                    &unhex(&case.encrypt_with_label.r#priv),
                    &encrypt_context("WrongLabel", &[]),
                    &[],
                )
                .is_err(),
            "a ciphertext must not open under a different label or context"
        );
    }

    assert!(ran > 0, "at least one ciphersuite in the vectors is supported");
    assert!(
        covered_pinned,
        "the ciphersuite this project pins ({PINNED:#06x}) must be among those run"
    );
    println!("crypto-basics: {ran} ciphersuite(s) matched the published answers");
}

// ---- key-schedule ----------------------------------------------------------

#[test]
fn key_schedule_vectors_match() {
    let provider = OpenMlsRustCrypto::default();
    let cases: Vec<KeyScheduleTestVector> =
        serde_json::from_str(&vectors("key-schedule.json")).expect("key-schedule.json parses");
    assert!(!cases.is_empty(), "the vector file is not empty");

    // The library's runner returns Ok for a ciphersuite it does not support, so
    // the coverage check has to happen out here.
    let supported: Vec<u16> = provider
        .crypto()
        .supported_ciphersuites()
        .iter()
        .map(|suite| *suite as u16)
        .collect();
    assert!(
        supported.contains(&PINNED),
        "the provider must support the ciphersuite this project pins"
    );

    let mut ran = 0;
    for case in cases {
        let named = case.cipher_suite;
        if !supported.contains(&named) {
            continue;
        }
        key_schedule::run_test_vector(case, &provider)
            .unwrap_or_else(|error| panic!("key schedule vector for {named:#06x}: {error:?}"));
        ran += 1;
    }
    assert!(ran > 0, "at least one key-schedule vector ran");
    println!("key-schedule: {ran} ciphersuite(s) matched the published answers");
}

// ---- tree-math -------------------------------------------------------------

#[test]
fn tree_math_vectors_match() {
    let cases: Vec<kat_treemath::TreeMathTestVector> =
        serde_json::from_str(&vectors("tree-math.json")).expect("tree-math.json parses");
    assert!(!cases.is_empty(), "the vector file is not empty");

    let total = cases.len();
    for case in cases {
        kat_treemath::run_test_vector(case).expect("tree math matches the published answers");
    }
    println!("tree-math: {total} tree shapes matched the published answers");
}
