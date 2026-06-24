//! P7 (ADR-020 §13): a deterministic, sans-IO, `proptest`-driven LAN-trust
//! state-machine simulator — the **dynamic** sibling of the static
//! `src/conformance.rs` vector validator.
//!
//! `conformance.rs` pins the *static* wire shapes (canonical bytes, payload
//! round-trip, posture mapping, sealed confidentiality) against a committed,
//! language-neutral file. This file instead drives *randomized sequences of trust
//! transitions* (enroll / lapse / revoke / advance-clock / send / seal) across a
//! tiny mesh and asserts the real `sign`/`verify`/`seal`/`open` primitives agree
//! with a **pure reference oracle** at every step. The oracle is hand-derived from
//! the real `verify_envelope` / `open_sealed` bodies (anchor check → chain check →
//! expiry → revocation-by-fingerprint → signature → freshness sub-field), so a
//! divergence is either a real bug or a design misunderstanding — never papered
//! over with a looser assert.
//!
//! ## Determinism / sans-IO discipline
//!
//! - No `SystemTime::now`, no `rand` *inside the transition core*, no sockets.
//! - The clock is a **logical** `i64` of unix-seconds that only the
//!   `AdvanceClock` transition moves.
//! - The ONE impurity is cert minting, done ONCE for the whole test binary (a fixed
//!   seed, shared across all cases via a `OnceLock`; the invariants are independent of
//!   the specific cert bytes, so the real coverage is the randomized transition
//!   sequences). ES256 signatures are randomized, so we assert on verify **verdicts**,
//!   never on signature/envelope bytes. Minting is confined to `tempfile::tempdir()`.
//!
//! Run: `cargo test -p koi-certmesh --test trust_sim`.

use koi_certmesh::ca;
use koi_certmesh::envelope::{build_envelope, verify_envelope, FRESHNESS_WINDOW_SECS};
use koi_certmesh::sealed::{open_sealed, seal_passthrough};
use koi_certmesh::CertmeshPaths;
use koi_common::envelope::{Assurance, Envelope, Freshness};
use koi_common::posture::{Posture, PostureLevel};
use koi_common::sealed::Sealed;
use koi_crypto::pinning::fingerprints_match;
use proptest::prelude::*;
use std::sync::OnceLock;

/// Number of nodes in the simulated mesh (NodeIds `0..=3`).
const NUM_NODES: usize = 4;

/// A logical, deterministic base clock (unix seconds, fixed) for the targeted I5
/// freshness test, where the leaf-expiry edge is irrelevant. Chosen far from the
/// cert validity edge so the only verdict driver there is the freshness window.
const BASE_CLOCK: i64 = 1_700_000_000;

/// How far before the earliest leaf expiry the dynamic state-machine clock starts.
/// 30 days: every `Send`/`Seal` in a bounded (length 1..40) run lands comfortably
/// inside leaf validity, so the dynamic machine exercises the in-validity verdicts
/// (Anonymous / Authenticated / UnknownSigner / Revoked) and their freshness
/// sub-field — never the leaf-expiry edge. The `Expired` arm is owned by the targeted
/// `expired_arm_verify_and_open` test, which drives a real leaf to and past its
/// `not_after` deterministically. (Crossing 30 days here would need ≈26 of the rare
/// `AdvanceClock { 100_000 }` steps back-to-back — vanishingly improbable in 256
/// bounded cases — so the dynamic run is NOT a reliable Expired-arm exerciser.)
const CLOCK_START_BEFORE_EXPIRY_SECS: i64 = 30 * 24 * 3600;

// ── Immutable shared fixtures (minted ONCE per test binary, then read-only) ────

/// A leaf certificate minted under one of the mesh's CAs (or the foreign CA).
#[derive(Clone)]
struct Leaf {
    cert_pem: String,
    key_pem: String,
    /// SHA-256 fingerprint of the leaf DER (the revocation key).
    fingerprint: String,
    /// The leaf's `notAfter`, unix seconds — the oracle's expiry gate mirrors the
    /// impl's `now > not_after`.
    expires: i64,
    /// The authoritative CN baked into the cert (== the node's name).
    cn: String,
}

/// The immutable cryptographic material for one simulation case.
struct Fixtures {
    /// This mesh's CA certificate PEM (the anchor a node pins when authenticated).
    ca_pem: String,
    /// One leaf per node, minted under this mesh's CA. `leaves[i].cn == "node-i"`.
    leaves: Vec<Leaf>,
    /// A leaf minted under a SECOND, independent CA — never chains to `ca_pem`.
    foreign_leaf: Leaf,
    /// The earliest `notAfter` across all mesh + foreign leaves (unix seconds). The
    /// dynamic clock origin is derived from this (30 days earlier) so every send in a
    /// bounded run lands inside validity — the dynamic machine stays short of the expiry
    /// edge by construction; the `Expired` arm is covered by the targeted test.
    earliest_expiry: i64,
}

impl Fixtures {
    /// Mint the whole fixture set ONCE from `entropy`. Reproducible: the mesh CA is
    /// seeded with `entropy`, the foreign CA with its bitwise-inverted twin (so it
    /// is a genuinely different, independent CA). Confined to a `tempdir`.
    fn mint(entropy: [u8; 32]) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");

        // Mesh CA.
        let mesh_paths = CertmeshPaths::with_data_dir(tmp.path().join("mesh"));
        let mesh_ca = ca::create_ca("sim-pass", &entropy, &mesh_paths)
            .expect("create mesh CA")
            .0;
        let ca_pem = mesh_ca.cert_pem.clone();

        let leaves: Vec<Leaf> = (0..NUM_NODES)
            .map(|i| {
                let cn = node_name(i);
                let issued = ca::issue_certificate(&mesh_ca, &cn, std::slice::from_ref(&cn), 90)
                    .expect("issue mesh leaf");
                Leaf {
                    cert_pem: issued.cert_pem,
                    key_pem: issued.key_pem,
                    fingerprint: issued.fingerprint,
                    expires: issued.expires.timestamp(),
                    cn,
                }
            })
            .collect();

        // Foreign CA (independent) + one foreign leaf.
        let foreign_entropy: [u8; 32] = {
            let mut e = entropy;
            for b in &mut e {
                *b = !*b;
            }
            e
        };
        let foreign_paths = CertmeshPaths::with_data_dir(tmp.path().join("foreign"));
        let foreign_ca = ca::create_ca("sim-pass", &foreign_entropy, &foreign_paths)
            .expect("create foreign CA")
            .0;
        let foreign_cn = "foreign-node".to_string();
        let foreign_issued = ca::issue_certificate(
            &foreign_ca,
            &foreign_cn,
            std::slice::from_ref(&foreign_cn),
            90,
        )
        .expect("issue foreign leaf");
        let foreign_leaf = Leaf {
            cert_pem: foreign_issued.cert_pem,
            key_pem: foreign_issued.key_pem,
            fingerprint: foreign_issued.fingerprint,
            expires: foreign_issued.expires.timestamp(),
            cn: foreign_cn,
        };

        let earliest_expiry = leaves
            .iter()
            .map(|l| l.expires)
            .chain(std::iter::once(foreign_leaf.expires))
            .min()
            .expect("at least one leaf");

        Fixtures {
            ca_pem,
            leaves,
            foreign_leaf,
            earliest_expiry,
        }
    }
}

fn node_name(i: usize) -> String {
    format!("node-{i}")
}

/// Mint the fixture set ONCE for the whole test binary (fixed deterministic seed) and
/// share it across every proptest case. The trust invariants are independent of the
/// specific cert bytes — the real coverage is the randomized TRANSITION SEQUENCES, not
/// the keys — so per-case minting only added cost (Argon2 CA creation dominated the
/// runtime). One shared, immutable fixture keeps the gate fast.
fn fixtures() -> &'static Fixtures {
    static FX: OnceLock<Fixtures> = OnceLock::new();
    FX.get_or_init(|| Fixtures::mint([7u8; 32]))
}

// ── The pure (sans-IO) model ───────────────────────────────────────────────────

/// Which leaf a node currently holds. A node may hold its own mesh leaf, or — to
/// exercise cross-CA isolation (I7) — the foreign leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LeafRef {
    /// The mesh leaf for node index `n`.
    Mesh(usize),
    /// The foreign-CA leaf (never chains to this mesh's anchor).
    Foreign,
}

/// One node's mutable trust state. Pure data — no locks, no IO.
#[derive(Clone, Debug)]
struct Node {
    posture: Posture,
    /// The leaf this node would sign with, if any (Open node → `None`).
    leaf: Option<LeafRef>,
    /// Whether this node pins the mesh CA as its verification anchor.
    has_anchor: bool,
    /// Fingerprints this node treats as revoked (best-effort, per-node).
    revoked: Vec<String>,
}

impl Node {
    fn open() -> Self {
        Node {
            posture: Posture::OPEN,
            leaf: None,
            has_anchor: false,
            revoked: Vec::new(),
        }
    }
}

/// The whole mesh model: nodes + the single logical clock.
struct Model {
    nodes: Vec<Node>,
    /// Logical clock, unix seconds. Seeded by [`Model::new`] (fixture-relative) and
    /// only ever moved by the `AdvanceClock` transition — never a wall clock.
    clock: i64,
}

impl Model {
    /// Start the dynamic clock 30 days before the earliest leaf expiry so every send in
    /// a bounded run lands inside leaf validity — the machine exercises the in-validity
    /// verdicts and their freshness sub-field, not the expiry edge. The `Expired` arm is
    /// covered deterministically by the targeted `expired_arm_verify_and_open` test.
    fn new(fx: &Fixtures) -> Self {
        Model {
            nodes: (0..NUM_NODES).map(|_| Node::open()).collect(),
            clock: fx.earliest_expiry - CLOCK_START_BEFORE_EXPIRY_SECS,
        }
    }
}

/// A transition the proptest strategy generates. Indices are pre-bounded into
/// `0..NUM_NODES` by the strategy so application never needs to clamp.
#[derive(Clone, Debug)]
enum Transition {
    /// Open → Authenticated: assign the node its mesh leaf + anchor, posture.signed.
    Enroll { node: usize },
    /// Like `Enroll` but the node is given the FOREIGN-CA leaf (signed posture +
    /// mesh anchor). Its envelopes never chain to the mesh anchor, so it exercises
    /// cross-CA isolation (I7) dynamically inside the state machine.
    EnrollForeign { node: usize },
    /// Authenticated → Open: drop the leaf, KEEP the anchor (a lapsed identity can
    /// still verify others), clear posture.signed.
    Lapse { node: usize },
    /// Push `node`'s mesh-leaf fingerprint into EVERY OTHER node's revoked set.
    Revoke { node: usize },
    /// Advance the logical clock by `delta` seconds.
    AdvanceClock { delta: i64 },
    /// `sender` builds an envelope (signed iff posture.signed) and `receiver`
    /// verifies it against its own anchor + revoked set at the current clock.
    Send { sender: usize, receiver: usize },
    /// As `Send` but via `seal_passthrough` / `open_sealed`.
    Seal { sender: usize, receiver: usize },
}

// ── The reference oracle ───────────────────────────────────────────────────────

/// The expected `verify`/`open`-inner verdict, hand-derived from the real
/// `verify_envelope` body. `signed_at_send` is the sender's `posture.signed` at the
/// instant the envelope was built (an envelope signs iff the node was signed then).
/// `leaf` is what the sender signed with (`None` when unsigned).
///
/// Mirrors only the impl arms REACHABLE from this state machine — which builds genuine,
/// well-formed, untampered, v1/ES256 envelopes via `build_envelope` and never mutates
/// the bytes:
/// 1. unsigned → `Anonymous{freshness}` (freshness only).
/// 2. receiver has no anchor → `Anonymous{freshness}`.
/// 3. leaf does not chain to the mesh anchor (foreign CA) → `UnknownSigner`.
/// 4. `now > leaf.expires` → `Expired`.
/// 5. leaf fingerprint in receiver.revoked → `Revoked`.
/// 6. otherwise → `Authenticated{cn, freshness}` (freshness is a sub-field; a
///    valid-but-stale signed envelope is STILL `Authenticated`, just `Stale`).
///
/// Explicitly OUT OF SCOPE here (the oracle does not model these arms because this
/// machine cannot reach them — it only builds genuine, well-formed, untampered v1/ES256
/// envelopes): the impl's `UnsupportedVersion` (a non-v1 / non-ES256 envelope),
/// `Malformed` (un-decodable base64 / DER fields), and the explicit `BadSignature` arm
/// (a tampered payload or swapped signature). They are unreachable from these
/// transitions, so the oracle deliberately omits them; this test makes no claim about
/// where else they are covered.
fn expected_verdict(
    signed_at_send: bool,
    leaf: Option<&Leaf>,
    leaf_is_mesh: bool,
    receiver: &Node,
    ts: i64,
    now: i64,
) -> Assurance {
    let freshness = if (now - ts).abs() <= FRESHNESS_WINDOW_SECS {
        Freshness::Fresh
    } else {
        Freshness::Stale
    };

    // Unsigned passthrough → anonymous, freshness only.
    if !signed_at_send || leaf.is_none() {
        return Assurance::Anonymous { freshness };
    }
    let leaf = leaf.expect("signed send has a leaf");

    // No trust anchor at the receiver → honest anonymous (Open verifier).
    if !receiver.has_anchor {
        return Assurance::Anonymous { freshness };
    }

    // Chain: a foreign-CA leaf never chains to this mesh's anchor.
    if !leaf_is_mesh {
        return reject(koi_common::envelope::RejectReason::UnknownSigner);
    }

    // Expiry: the impl rejects iff `now > not_after`. The leaf chained (mesh leaf),
    // so the verdict attributes its authoritative CN (ADR-022 §2).
    if now > leaf.expires {
        return reject_with(
            koi_common::envelope::RejectReason::Expired,
            Some(leaf.cn.clone()),
        );
    }

    // Revocation (best-effort, by fingerprint — constant-time match in the impl).
    if receiver
        .revoked
        .iter()
        .any(|f| fingerprints_match(f, &leaf.fingerprint))
    {
        return reject_with(
            koi_common::envelope::RejectReason::Revoked,
            Some(leaf.cn.clone()),
        );
    }

    // A well-formed, freshly-minted leaf that chains + is unrevoked + unexpired
    // always passes the signature check (we never tamper here), so the verdict is
    // Authenticated with the freshness sub-field.
    Assurance::Authenticated {
        cn: leaf.cn.clone(),
        freshness,
    }
}

fn reject(reason: koi_common::envelope::RejectReason) -> Assurance {
    Assurance::Rejected {
        reason,
        signer_cn: None,
    }
}

fn reject_with(reason: koi_common::envelope::RejectReason, signer_cn: Option<String>) -> Assurance {
    Assurance::Rejected { reason, signer_cn }
}

// ── Helpers that bridge model ↔ real primitives ────────────────────────────────

/// Resolve a node's `LeafRef` to the concrete fixture `Leaf` (and whether it is a
/// mesh leaf, i.e. chains to this mesh's anchor).
fn resolve_leaf(fx: &Fixtures, leaf: Option<LeafRef>) -> (Option<&Leaf>, bool) {
    match leaf {
        Some(LeafRef::Mesh(n)) => (Some(&fx.leaves[n]), true),
        Some(LeafRef::Foreign) => (Some(&fx.foreign_leaf), false),
        None => (None, false),
    }
}

/// Build the `signer` argument `build_envelope`/`seal_passthrough` expect: `Some`
/// iff the node is signed at send AND actually holds a leaf.
fn signer_for<'a>(node: &Node, leaf: Option<&'a Leaf>) -> Option<(&'a str, &'a str)> {
    if node.posture.signed {
        leaf.map(|l| (l.key_pem.as_str(), l.cert_pem.as_str()))
    } else {
        None
    }
}

/// The receiver's anchor argument: `Some(ca_pem)` iff it pins the mesh CA.
fn anchor_for<'a>(fx: &'a Fixtures, receiver: &Node) -> Option<&'a str> {
    receiver.has_anchor.then_some(fx.ca_pem.as_str())
}

/// I8: assert an `Envelope` survives a serde_json round-trip unchanged.
fn assert_wire_roundtrip_envelope(env: &Envelope) -> Result<(), TestCaseError> {
    let json = serde_json::to_string(env).expect("envelope serializes");
    let back: Envelope = serde_json::from_str(&json).expect("envelope deserializes");
    prop_assert_eq!(
        &back,
        env,
        "I8: envelope serde round-trip changed the value"
    );
    Ok(())
}

/// I8: assert a `Sealed` survives a serde_json round-trip unchanged.
fn assert_wire_roundtrip_sealed(sealed: &Sealed) -> Result<(), TestCaseError> {
    let json = serde_json::to_string(sealed).expect("sealed serializes");
    let back: Sealed = serde_json::from_str(&json).expect("sealed deserializes");
    prop_assert_eq!(
        &back,
        sealed,
        "I8: sealed serde round-trip changed the value"
    );
    Ok(())
}

// ── The transition applier (pure model mutation + real-vs-oracle checks) ───────

/// Apply one transition: mutate the model, and for Send/Seal exercise the real
/// primitives and assert they agree with the oracle plus the standing invariants.
fn apply(model: &mut Model, fx: &Fixtures, t: &Transition) -> Result<(), TestCaseError> {
    match *t {
        Transition::Enroll { node } => {
            let n = &mut model.nodes[node];
            n.leaf = Some(LeafRef::Mesh(node));
            n.has_anchor = true;
            n.posture = Posture::new(true, n.posture.encrypted);
        }
        Transition::EnrollForeign { node } => {
            let n = &mut model.nodes[node];
            n.leaf = Some(LeafRef::Foreign);
            n.has_anchor = true;
            n.posture = Posture::new(true, n.posture.encrypted);
        }
        Transition::Lapse { node } => {
            let n = &mut model.nodes[node];
            n.leaf = None;
            // Keep the anchor: a lapsed node still verifies others.
            n.posture = Posture::new(false, false);
        }
        Transition::Revoke { node } => {
            let fp = fx.leaves[node].fingerprint.clone();
            for (i, other) in model.nodes.iter_mut().enumerate() {
                if i != node && !other.revoked.iter().any(|f| f == &fp) {
                    other.revoked.push(fp.clone());
                }
            }
        }
        Transition::AdvanceClock { delta } => {
            model.clock += delta;
        }
        Transition::Send { sender, receiver } => {
            check_send(model, fx, sender, receiver)?;
        }
        Transition::Seal { sender, receiver } => {
            check_seal(model, fx, sender, receiver)?;
        }
    }
    Ok(())
}

/// Exercise `build_envelope` + `verify_envelope` for sender→receiver, asserting the
/// real verdict matches the oracle and the standing invariants (I1, I3, I4, I8).
fn check_send(
    model: &Model,
    fx: &Fixtures,
    sender_idx: usize,
    receiver_idx: usize,
) -> Result<(), TestCaseError> {
    let sender = &model.nodes[sender_idx];
    let receiver = &model.nodes[receiver_idx];
    let now = model.clock;
    // Sign at "now" — the freshness window is then exercised by later AdvanceClock
    // (the oracle uses the message ts vs the verify-time clock).
    let ts = now;

    let (leaf, leaf_is_mesh) = resolve_leaf(fx, sender.leaf);
    let signer = signer_for(sender, leaf);
    let signed_at_send = signer.is_some();

    let nonce = [0u8; 16]; // deterministic; nonce content does not affect the verdict
    let env = build_envelope(signer, b"sim-payload", &nonce, ts);

    // I8: wire round-trip survives unchanged.
    assert_wire_roundtrip_envelope(&env)?;

    // I3: zero-cost-in-Open — an unsigned send carries no signature block.
    if !signed_at_send {
        prop_assert!(
            env.sig.is_none(),
            "I3: an Open (unsigned) send must not carry an ES256 signature block"
        );
    }

    let got = verify_envelope(&env, anchor_for(fx, receiver), &receiver.revoked, now);
    let want = expected_verdict(signed_at_send, leaf, leaf_is_mesh, receiver, ts, now);

    // I1: the real verdict equals the oracle.
    prop_assert_eq!(
        &got,
        &want,
        "I1: verify_envelope disagreed with the oracle (sender={}, receiver={}, signed_at_send={}, leaf_is_mesh={}, now={}, ts={})",
        sender_idx,
        receiver_idx,
        signed_at_send,
        leaf_is_mesh,
        now,
        ts
    );

    // I3 (continued): an Open send always verifies to Anonymous — never
    // Authenticated, never Rejected.
    if !signed_at_send {
        prop_assert!(
            matches!(got, Assurance::Anonymous { .. }),
            "I3: an Open send must verify to Anonymous, got {:?}",
            got
        );
    }

    // I7: a foreign-CA leaf is always UnknownSigner at a receiver that has an
    // anchor (and Anonymous at an anchorless receiver — folded into I1).
    if signed_at_send && !leaf_is_mesh && receiver.has_anchor {
        prop_assert_eq!(
            &got,
            &reject(koi_common::envelope::RejectReason::UnknownSigner),
            "I7: a foreign-CA leaf must be UnknownSigner at an anchored receiver"
        );
    }

    // I4: the one identity door — Some IFF Authenticated{Fresh}.
    assert_identity_door(&got)?;

    Ok(())
}

/// Exercise `seal_passthrough` + `open_sealed` for sender→receiver, asserting the
/// real behavior matches the oracle and the standing invariants (I2, I6, I8).
fn check_seal(
    model: &Model,
    fx: &Fixtures,
    sender_idx: usize,
    receiver_idx: usize,
) -> Result<(), TestCaseError> {
    let sender = &model.nodes[sender_idx];
    let receiver = &model.nodes[receiver_idx];
    let now = model.clock;
    let ts = now;

    let (leaf, leaf_is_mesh) = resolve_leaf(fx, sender.leaf);
    let signer = signer_for(sender, leaf);
    let signed_at_send = signer.is_some();

    let payload = b"sim-secret-payload";
    let nonce = [1u8; 16];
    let sealed = seal_passthrough(signer, payload, &nonce, ts);

    // I8: wire round-trip survives unchanged.
    assert_wire_roundtrip_sealed(&sealed)?;

    let inner_verdict = expected_verdict(signed_at_send, leaf, leaf_is_mesh, receiver, ts, now);
    let result = open_sealed(&sealed, anchor_for(fx, receiver), &receiver.revoked, now);

    // I2: Ok(payload byte-equal) IFF the inner verdict is NOT Rejected; a Rejected
    // inner verdict → Err AND no bytes.
    if inner_verdict.is_rejected() {
        prop_assert!(
            result.is_err(),
            "I2: a Rejected inner verdict ({:?}) must make open_sealed Err, not Ok",
            inner_verdict
        );
    } else {
        let opened = match result {
            Ok(o) => o,
            Err(e) => {
                return Err(TestCaseError::fail(format!(
                "I2: a non-Rejected inner verdict ({inner_verdict:?}) must open Ok, got Err: {e}"
            )))
            }
        };
        prop_assert_eq!(
            &opened.payload,
            &payload.to_vec(),
            "I2: opened payload must be byte-equal to the sealed payload"
        );
        // The opened assurance must equal the inner verdict the oracle predicted.
        prop_assert_eq!(
            &opened.assurance,
            &inner_verdict,
            "I2: opened assurance disagreed with the oracle (sender={}, receiver={})",
            sender_idx,
            receiver_idx
        );
        // I4 also holds on the opened assurance.
        assert_identity_door(&opened.assurance)?;
        // I6: seal is v0 passthrough — Confidential is NOT real encryption; the
        // confidentiality level is always `None` (passthrough), behaving exactly
        // like Authenticated/Anonymous integrity, never a secrecy claim.
        prop_assert_eq!(
            opened.confidentiality,
            koi_common::sealed::Confidentiality::None,
            "I6: v0 seal must report passthrough confidentiality (None), never GroupKey"
        );
    }

    Ok(())
}

/// I4: `Assurance::identity()` is `Some` ONLY for `Authenticated { Fresh }`.
fn assert_identity_door(a: &Assurance) -> Result<(), TestCaseError> {
    let id = a.identity();
    match a {
        Assurance::Authenticated {
            cn,
            freshness: Freshness::Fresh,
        } => prop_assert_eq!(
            id,
            Some(cn.as_str()),
            "I4: Authenticated+Fresh must open the identity door"
        ),
        _ => prop_assert!(
            id.is_none(),
            "I4: only Authenticated+Fresh opens the identity door; got {:?} → identity {:?}",
            a,
            id
        ),
    }
    Ok(())
}

// ── Strategies ─────────────────────────────────────────────────────────────────

fn node_idx() -> impl Strategy<Value = usize> {
    0..NUM_NODES
}

/// Clock deltas chosen to straddle the freshness window edge (300s): 0, mid,
/// just-inside (299), just-outside (301), well-outside (600), and a large jump
/// (100000s ≈ 1.16 days). The big jump exercises deep staleness (a long gap between a
/// message's `ts` and the verify-time clock → `Stale` + the closed identity door)
/// without ever reaching leaf expiry: with a 30-day head start and bounded (1..40)
/// runs, crossing validity would take ≈26 back-to-back big jumps and effectively never
/// happens — the `Expired` arm is owned by `expired_arm_verify_and_open` instead.
fn clock_delta() -> impl Strategy<Value = i64> {
    prop_oneof![
        Just(0i64),
        Just(30),
        Just(299),
        Just(301),
        Just(600),
        Just(100_000),
    ]
}

fn transition() -> impl Strategy<Value = Transition> {
    prop_oneof![
        node_idx().prop_map(|node| Transition::Enroll { node }),
        node_idx().prop_map(|node| Transition::EnrollForeign { node }),
        node_idx().prop_map(|node| Transition::Lapse { node }),
        node_idx().prop_map(|node| Transition::Revoke { node }),
        clock_delta().prop_map(|delta| Transition::AdvanceClock { delta }),
        (node_idx(), node_idx())
            .prop_map(|(sender, receiver)| Transition::Send { sender, receiver }),
        (node_idx(), node_idx())
            .prop_map(|(sender, receiver)| Transition::Seal { sender, receiver }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// The master simulation: mint a fixture set, then apply a random transition
    /// sequence, asserting the real primitives agree with the oracle (I1, I2, I3,
    /// I4, I7) and the wire round-trip (I8) at every Send/Seal.
    #[test]
    fn lan_trust_state_machine(
        transitions in prop::collection::vec(transition(), 1..40),
    ) {
        let fx = fixtures();
        let mut model = Model::new(fx);
        for t in &transitions {
            apply(&mut model, fx, t)?;
        }
    }
}

// ── Targeted invariant tests (I5, I6) that need a constructed scenario ─────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// I5 (freshness-monotone): re-verifying ONE fixed signed message at growing
    /// `|now - ts|` flips `Fresh → Stale` exactly at the window edge and closes the
    /// identity door — but the underlying Authenticated/Rejected *kind* never
    /// changes (a Rejected verdict is clock-independent and never becomes
    /// Authenticated; an Authenticated one never becomes Rejected by the clock
    /// alone).
    #[test]
    fn freshness_is_monotone_and_clock_cannot_upgrade(
        revoked in any::<bool>(),
        foreign in any::<bool>(),
    ) {
        let fx = fixtures();
        let ts = BASE_CLOCK;

        // Sign ONE message from node 0 (signed). If `foreign`, sign with the foreign
        // leaf so the base verdict is Rejected(UnknownSigner) — clock-independent.
        let leaf = if foreign { &fx.foreign_leaf } else { &fx.leaves[0] };
        let env = build_envelope(
            Some((leaf.key_pem.as_str(), leaf.cert_pem.as_str())),
            b"fixed-message",
            &[2u8; 16],
            ts,
        );

        let revoked_set: Vec<String> = if revoked {
            vec![leaf.fingerprint.clone()]
        } else {
            vec![]
        };
        let anchor = Some(fx.ca_pem.as_str());

        // The expected REJECT-or-not is fixed by foreign/revoked, independent of clock.
        let base_rejected = foreign || revoked;

        // Walk |now - ts| across the window edge.
        let offsets = [
            0i64,
            FRESHNESS_WINDOW_SECS - 1, // inside
            FRESHNESS_WINDOW_SECS,     // boundary (still Fresh: `<=`)
            FRESHNESS_WINDOW_SECS + 1, // outside → Stale
            FRESHNESS_WINDOW_SECS + 1000,
        ];

        for off in offsets {
            let now = ts + off;
            let got = verify_envelope(&env, anchor, &revoked_set, now);
            let within = off.abs() <= FRESHNESS_WINDOW_SECS;

            if base_rejected {
                // Clock-independent: Rejected stays Rejected and never authenticates.
                prop_assert!(
                    got.is_rejected(),
                    "I5: a Rejected verdict must be clock-independent (off={off}), got {got:?}"
                );
                prop_assert_eq!(got.identity(), None, "I5: Rejected never opens the identity door");
            } else if within {
                prop_assert_eq!(
                    got,
                    Assurance::Authenticated { cn: leaf.cn.clone(), freshness: Freshness::Fresh },
                    "I5: within the window must be Authenticated+Fresh (off={})", off
                );
            } else {
                // Outside the window: still Authenticated (the signature is valid),
                // but Stale — and the identity door is now CLOSED.
                prop_assert_eq!(
                    &got,
                    &Assurance::Authenticated { cn: leaf.cn.clone(), freshness: Freshness::Stale },
                    "I5: outside the window must be Authenticated+Stale (off={})", off
                );
                prop_assert_eq!(
                    got.identity(),
                    None,
                    "I5: Stale closes the identity door (off={})", off
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Expired-arm (targeted): the `lan_trust_state_machine` dynamic run stays inside
    /// leaf validity (its bounded clock never reaches expiry — see that test's note), so
    /// the `now > leaf.not_after` arm of the REAL `verify_envelope` / `open_sealed` is
    /// proven here against a real mesh leaf and the real anchor:
    ///
    /// - `now == leaf.expires` (== `not_after`) → `Authenticated` (the impl rejects only
    ///   strictly `now > not_after`; equality is still valid). We sign at `ts = expires`
    ///   so freshness is `Fresh` at the edge → the identity door is open.
    /// - `now == expires + 1` → `Rejected { Expired }` (the first second past validity).
    /// - `now == expires + large` → still `Rejected { Expired }` (never re-authenticates).
    ///
    /// The expiry gate fires before freshness, so a past-expiry verdict is `Expired`
    /// regardless of `|now - ts|`. `node`/`big` are randomized to spread the leaf used and
    /// the "large" overshoot; the asserted edges are deterministic.
    #[test]
    fn expired_arm_verify_and_open(
        node in 0..NUM_NODES,
        big in 10_000i64..10_000_000i64,
    ) {
        let fx = fixtures();
        let leaf = &fx.leaves[node];
        let anchor = Some(fx.ca_pem.as_str());
        let expires = leaf.expires;

        // Sign at exactly the expiry instant so freshness is Fresh at `now == expires`.
        let env = build_envelope(
            Some((leaf.key_pem.as_str(), leaf.cert_pem.as_str())),
            b"expiring-message",
            &[3u8; 16],
            expires,
        );

        // At the expiry edge: still Authenticated (the impl rejects only `now > not_after`).
        let at_edge = verify_envelope(&env, anchor, &[], expires);
        prop_assert_eq!(
            &at_edge,
            &Assurance::Authenticated { cn: leaf.cn.clone(), freshness: Freshness::Fresh },
            "Expired arm: now == not_after is NOT expired (equality is valid)"
        );
        prop_assert_eq!(
            at_edge.identity(),
            Some(leaf.cn.as_str()),
            "Expired arm: the at-edge Authenticated+Fresh verdict opens the identity door"
        );

        // One second past validity → Expired, attributing the chained leaf's CN.
        let just_past = verify_envelope(&env, anchor, &[], expires + 1);
        prop_assert_eq!(
            &just_past,
            &reject_with(
                koi_common::envelope::RejectReason::Expired,
                Some(leaf.cn.clone())
            ),
            "Expired arm: now == expires + 1 must be Rejected{{Expired}}"
        );
        prop_assert_eq!(just_past.identity(), None, "Expired arm: Expired closes the door");

        // Far past validity → still Expired (never re-authenticates with more elapsed time).
        let far_past = verify_envelope(&env, anchor, &[], expires + big);
        prop_assert_eq!(
            &far_past,
            &reject_with(
                koi_common::envelope::RejectReason::Expired,
                Some(leaf.cn.clone())
            ),
            "Expired arm: now == expires + {} must still be Rejected{{Expired}}", big
        );

        // Symmetric `open_sealed` expired case: a Rejected{Expired} inner verdict yields
        // an Err and NEVER the bytes (misuse-resistance), at +1 and far past.
        let sealed = seal_passthrough(
            Some((leaf.key_pem.as_str(), leaf.cert_pem.as_str())),
            b"expiring-secret",
            &[4u8; 16],
            expires,
        );

        // At the edge it still opens (Authenticated) and the bytes survive.
        let opened_at_edge = open_sealed(&sealed, anchor, &[], expires)
            .expect("open_sealed at the expiry edge succeeds (not yet expired)");
        prop_assert_eq!(
            &opened_at_edge.payload,
            &b"expiring-secret".to_vec(),
            "Expired arm: at the edge the sealed payload survives"
        );

        for off in [1i64, big] {
            let err = open_sealed(&sealed, anchor, &[], expires + off)
                .expect_err("open_sealed past expiry must Err, never return bytes");
            prop_assert!(
                err.to_string().contains("Expired"),
                "Expired arm: open_sealed past expiry must report Expired (off={}), got: {}",
                off,
                err
            );
        }
    }
}

/// I6 (posture-oracle purity): `Posture.level()` is a pure function of
/// `(signed, encrypted)`. Open < Authenticated < Confidential; `encrypted`
/// without `signed` collapses to Open. Note: seal is still v0 passthrough, so
/// Confidential *behaves* like Authenticated at the wire — we assert the LEVEL
/// mapping here (the seal-behaves-like-authenticated half is asserted by I6 in
/// `check_seal`, which verifies the confidentiality is always `None`).
#[test]
fn posture_level_is_pure() {
    let cases = [
        (false, false, PostureLevel::Open),
        (false, true, PostureLevel::Open), // encrypted-without-signed collapses
        (true, false, PostureLevel::Authenticated),
        (true, true, PostureLevel::Confidential),
    ];
    for (signed, encrypted, expect) in cases {
        let p = Posture::new(signed, encrypted);
        assert_eq!(p.level(), expect, "level({signed},{encrypted})");
        // Purity: same inputs → same output, every time.
        assert_eq!(p.level(), Posture::new(signed, encrypted).level());
    }
    // The ladder ordering is real (each rung a superset of the last).
    assert!(PostureLevel::Open < PostureLevel::Authenticated);
    assert!(PostureLevel::Authenticated < PostureLevel::Confidential);
}
