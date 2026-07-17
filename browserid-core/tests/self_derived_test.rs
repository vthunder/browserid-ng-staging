//! End-to-end adversarial tests for the phase-1 self-derivation path
//! (self-derivation design §2, agent-as-self). These drive the public
//! presentation surface — `BackedAssertion::parse` / `verify` — exactly as an
//! RP (and, later, sbo-core via the shared verifier) would.

use browserid_core::{
    Assertion, Authority, BackedAssertion, Certificate, Error, KeyPair, StatusRef, Warrant,
};
use chrono::Duration;

const DOMAIN: &str = "sandmill.org";
const BASE: &str = "danmills@sandmill.org";
const RP: &str = "sbo://mingo";

fn status() -> StatusRef {
    StatusRef {
        uri: "https://browserid.me/.well-known/browserid-status".into(),
        idx: 42,
    }
}

struct Setup {
    domain_key: KeyPair,
    base_key: KeyPair,
    agent_key: KeyPair,
    base_cert: Certificate,
}

fn setup_with_base(validity: Duration) -> Setup {
    let domain_key = KeyPair::generate();
    let base_key = KeyPair::generate();
    let agent_key = KeyPair::generate();
    let base_cert =
        Certificate::create(DOMAIN, BASE, &base_key.public_key(), validity, &domain_key).unwrap();
    Setup { domain_key, base_key, agent_key, base_cert }
}

fn setup() -> Setup {
    setup_with_base(Duration::hours(24))
}

fn derived(s: &Setup) -> Certificate {
    Certificate::create_self_derived_agent(
        &s.base_cert,
        &s.agent_key.public_key(),
        &s.base_key,
        Duration::hours(8),
        status(),
    )
    .unwrap()
}

// A self-derived agent warrant: signed by the BASE key, embedding the BASE cert
// as parent-cert. No status ref — phase-1 self-derived path is fail-open (no
// registrar pinning), so the warrant needs none.
fn warrant(s: &Setup, agent_email: &str, aud: &str) -> Warrant {
    Warrant::create(
        &s.base_cert,
        agent_email,
        aud,
        Some(vec!["admin".into()]),
        Duration::days(30),
        &s.base_key,
    )
    .unwrap()
}

fn assertion(s: &Setup, aud: &str) -> Assertion {
    Assertion::create(aud, Duration::minutes(5), &s.agent_key).unwrap()
}

// Re-encode a cert's claims after `mutate`, re-signed with `key`.
fn remint(cert: &Certificate, key: &KeyPair, mutate: impl Fn(&mut serde_json::Value)) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let mut claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(cert.encoded().split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    mutate(&mut claims);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let msg = format!("{header_b64}.{claims_b64}");
    let sig = key.sign(msg.as_bytes());
    format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn wire(base: &Certificate, leaf: &str, w: &Warrant, a: &Assertion) -> String {
    format!("{}~{}~{}~{}", base.encoded(), leaf, w.encoded(), a.encoded())
}

// ---- POSITIVE ----

#[test]
fn positive_agent_as_self_verifies_and_surfaces_scopes() {
    let s = setup();
    let d = derived(&s);
    let backed = BackedAssertion::new_self_derived_agent(
        s.base_cert.clone(),
        d,
        warrant(&s, BASE, RP),
        assertion(&s, RP),
    );

    // Round-trip through the wire so parse + check_structure run too.
    let parsed = BackedAssertion::parse(&backed.encode()).unwrap();
    let verified = parsed
        .verify(RP, |dom| {
            assert_eq!(dom, DOMAIN, "domain key looked up for the base domain");
            Ok(s.domain_key.public_key())
        })
        .unwrap();

    assert!(verified.is_agent(), "agent-ness is structurally prominent");
    assert_eq!(verified.email(), BASE, "acts as the base identity");
    let a = verified.agent().expect("agent attribution");
    assert_eq!(a.acts_as, BASE);
    assert_eq!(a.parent, BASE);
    assert_eq!(a.scopes, vec!["admin"], "warrant scopes surfaced");
}

// ---- name-constraint forgeries ----

#[test]
fn cannot_forge_different_local_part() {
    let s = setup();
    let bob = remint(&derived(&s), &s.base_key, |c| {
        c["principal"]["email"] = "bob@sandmill.org".into()
    });
    let w = wire(&s.base_cert, &bob, &warrant(&s, BASE, RP), &assertion(&s, RP));
    let parsed = BackedAssertion::parse(&w).unwrap();
    let e = parsed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(e.to_string().contains("name constraint"), "{e}");
}

#[test]
fn cannot_forge_cross_domain() {
    let s = setup();
    let other = remint(&derived(&s), &s.base_key, |c| {
        c["principal"]["email"] = "danmills@other.org".into()
    });
    let w = wire(&s.base_cert, &other, &warrant(&s, BASE, RP), &assertion(&s, RP));
    let parsed = BackedAssertion::parse(&w).unwrap();
    let e = parsed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(e.to_string().contains("name constraint"), "{e}");
}

// ---- authority: cannot self-sign a full-authority identity via this path ----

#[test]
fn self_derived_authority_open_rejected() {
    let s = setup();
    let open = remint(&derived(&s), &s.base_key, |c| c["authority"] = "open".into());
    let w = wire(&s.base_cert, &open, &warrant(&s, BASE, RP), &assertion(&s, RP));
    let parsed = BackedAssertion::parse(&w).unwrap();
    let e = parsed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(e.to_string().contains("authority=closed"), "{e}");
}

#[test]
fn self_signed_plain_identity_cert_rejected() {
    // The other shape of "regular identity via self-signing": a plain (typ=None)
    // cert self-signed by the base key and claiming to be domain-issued. The
    // classic path checks the domain signature and rejects it.
    let s = setup();
    let self_signed_plain = Certificate::create(
        DOMAIN,
        BASE,
        &s.agent_key.public_key(),
        Duration::hours(8),
        &s.base_key, // NOT the domain key
    )
    .unwrap();
    let a = assertion(&s, RP);
    let backed = BackedAssertion::new(self_signed_plain, a);
    let e = backed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(matches!(e, Error::SignatureVerificationFailed), "{e:?}");
}

// ---- expiry / signature / structural ----

#[test]
fn expired_base_cert_rejected() {
    // Base already expired; the derived leaf is re-minted with a far-future exp
    // so the rejection is specifically the base freshness check (OQ-3), not the
    // leaf's own expiry.
    let s = setup_with_base(Duration::seconds(-10));
    let d0 = derived(&s);
    let far = (chrono::Utc::now() + Duration::days(365)).timestamp();
    let d = remint(&d0, &s.base_key, |c| c["exp"] = far.into());
    let w = wire(&s.base_cert, &d, &warrant(&s, BASE, RP), &assertion(&s, RP));
    let parsed = BackedAssertion::parse(&w).unwrap();
    let e = parsed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(matches!(e, Error::CertificateExpired), "{e:?}");
}

#[test]
fn derived_not_signed_by_base_key_rejected() {
    let s = setup();
    let rogue = KeyPair::generate();
    let forged = Certificate::create_self_derived_agent(
        &s.base_cert,
        &s.agent_key.public_key(),
        &rogue, // not the base key
        Duration::hours(8),
        status(),
    )
    .unwrap();
    let backed = BackedAssertion::new_self_derived_agent(
        s.base_cert.clone(),
        forged,
        warrant(&s, BASE, RP),
        assertion(&s, RP),
    );
    let e = backed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(matches!(e, Error::SignatureVerificationFailed), "{e:?}");
}

#[test]
fn base_cert_not_domain_signed_rejected() {
    let s = setup();
    let rogue_idp = KeyPair::generate();
    // A base cert signed by a key that is not the real domain key.
    let bad_base =
        Certificate::create(DOMAIN, BASE, &s.base_key.public_key(), Duration::hours(24), &rogue_idp)
            .unwrap();
    let d = Certificate::create_self_derived_agent(
        &bad_base,
        &s.agent_key.public_key(),
        &s.base_key,
        Duration::hours(8),
        status(),
    )
    .unwrap();
    let backed = BackedAssertion::new_self_derived_agent(
        bad_base,
        d,
        warrant(&s, BASE, RP),
        assertion(&s, RP),
    );
    // Lookup returns the real domain key; the base was signed by the rogue key.
    let e = backed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(matches!(e, Error::SignatureVerificationFailed), "{e:?}");
}

#[test]
fn self_agent_leaf_without_warrant_rejected() {
    let s = setup();
    let d = derived(&s);
    // Bare `[base, self_agent]~assertion` — no warrant — an inert agent.
    let bare = format!(
        "{}~{}~{}",
        s.base_cert.encoded(),
        d.encoded(),
        assertion(&s, RP).encoded()
    );
    assert!(matches!(
        BackedAssertion::parse(&bare),
        Err(Error::WarrantRequired)
    ));
}

#[test]
fn self_agent_must_be_leaf_not_intermediate() {
    // A self-agent cert sitting before the leaf is a malformed chain.
    let s = setup();
    let d = derived(&s);
    let plain_leaf = Certificate::create(
        DOMAIN,
        BASE,
        &s.agent_key.public_key(),
        Duration::hours(1),
        &s.domain_key,
    )
    .unwrap();
    let bad = format!(
        "{}~{}~{}",
        d.encoded(),
        plain_leaf.encoded(),
        assertion(&s, RP).encoded()
    );
    let e = BackedAssertion::parse(&bad).unwrap_err().to_string();
    assert!(e.contains("must be the leaf"), "{e}");
}

#[test]
fn wrong_audience_rejected() {
    let s = setup();
    let d = derived(&s);
    // Warrant + assertion for a different audience than we verify against.
    let backed = BackedAssertion::new_self_derived_agent(
        s.base_cert.clone(),
        d,
        warrant(&s, BASE, "sbo://other"),
        assertion(&s, "sbo://other"),
    );
    let e = backed
        .verify(RP, |_| Ok(s.domain_key.public_key()))
        .unwrap_err();
    assert!(matches!(e, Error::AudienceMismatch { .. }), "{e:?}");
}

#[test]
fn authority_field_is_universal_on_base_and_agent() {
    // Sanity: the universal authority field is set on every constructor.
    let s = setup();
    assert_eq!(s.base_cert.authority(), Some(Authority::Open));
    assert_eq!(derived(&s).authority(), Some(Authority::Closed));
}
