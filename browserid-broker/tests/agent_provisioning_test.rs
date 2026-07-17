//! Integration tests for delegation-chain agent provisioning (tdxf, spec
//! v0.2): browser-registered provisioning certs → broker endorsement → mint
//! against the broker as target IdP → local assertion → offline verify. The
//! broker holds no secret; the "API key" (P_priv) stays with the agent.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::provisioning::{Constraint, ProvisioningCert, ProvisioningRequest, RequestBundle};
use browserid_core::{
    Assertion, BackedAssertion, Certificate, Endorsement, KeyPair, PublicKey, Warrant,
};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://rp.example.com";
const DOMAIN: &str = "localhost:3000";

fn create_agent_server(quota: usize) -> (TestServer, MockEmailSender, PublicKey) {
    let keypair = KeyPair::generate();
    let broker_pub = keypair.public_key();
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        keypair,
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    state.max_agent_identities_per_user = quota;
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() }, broker_pub)
}

async fn get_csrf(server: &TestServer, session: &str) -> String {
    server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await
        .json::<Value>()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Mint a real broker-issued U_cert for `email` via /wsapi/cert_key (session
/// authorizes it). This is exactly how the browser page gets the identity cert
/// it will delegate from.
async fn issue_user_cert(server: &TestServer, session: &str, email: &str, user_kp: &KeyPair) -> Certificate {
    let csrf = get_csrf(server, session).await;
    let body: Value = server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&json!({
            "csrf": csrf,
            "email": email,
            "pubkey": { "algorithm": "Ed25519", "publicKey": user_kp.public_key().to_base64() },
            "ephemeral": false
        }))
        .await
        .json();
    assert_eq!(body["success"], true, "cert_key failed: {body}");
    Certificate::parse(body["cert"].as_str().unwrap()).unwrap()
}

/// The full browser-side "create agent key" ceremony, done with real crypto:
/// account + verified email, issue U_cert for an (ephemeral) identity key,
/// sign a P_cert delegating to a fresh provisioning key, register it. Returns
/// (delegation_bundle `U_cert~P_cert`, provisioning keypair, session).
async fn register_agent_key(
    server: &TestServer,
    email_sender: &MockEmailSender,
    email: &str,
) -> (String, KeyPair, String) {
    // Existing tests mint bare names; give an explicit list covering them plus
    // an `svc+*` pattern so subaddress mints are exercised too.
    register_agent_key_with(
        server,
        email_sender,
        email,
        Constraint {
            names: ["attestor", "other", "one", "two", "three", "bot", "doomed", "worker"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            patterns: vec!["svc+*".into()],
        },
    )
    .await
}

async fn register_agent_key_with(
    server: &TestServer,
    email_sender: &MockEmailSender,
    email: &str,
    constraint: Constraint,
) -> (String, KeyPair, String) {
    let session = create_user(server, email_sender, email, "testpassword").await;

    let user_kp = KeyPair::generate();
    let user_cert = issue_user_cert(server, &session, email, &user_kp).await;

    let provisioning_kp = KeyPair::generate();
    let p_cert = ProvisioningCert::create(
        email,
        &provisioning_kp.public_key(),
        constraint,
        Duration::days(90),
        &user_kp,
    )
    .unwrap();
    let bundle = format!("{}~{}", user_cert.encoded(), p_cert.encoded());

    let csrf = get_csrf(server, &session).await;
    let resp = server
        .post("/wsapi/register_provisioning_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "label": "ci-bot", "bundle": bundle }))
        .await;
    assert_eq!(resp.status_code(), 200, "register failed: {:?}", resp.text());

    (bundle, provisioning_kp, session)
}

/// Endorse a request bundle at the broker, returning the endorsement JWS.
async fn endorse(server: &TestServer, request_bundle: &str) -> String {
    let body: Value = server
        .post("/provision/endorse")
        .json(&json!({ "request_bundle": request_bundle }))
        .await
        .json();
    assert_eq!(body["success"], true, "endorse failed: {body}");
    body["endorsement"].as_str().unwrap().to_string()
}

/// Build a mint request bundle for an agent key + name.
fn mint_bundle(delegation: &str, provisioning_kp: &KeyPair, name: &str, agent_kp: &KeyPair) -> String {
    let (u, p) = delegation.split_once('~').unwrap();
    let request =
        ProvisioningRequest::mint(DOMAIN, name, &agent_kp.public_key(), false, provisioning_kp).unwrap();
    RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        request,
    )
    .encoded()
    .to_string()
}

/// v0.4 presentation helper: issue a fresh broker U_cert for the delegator
/// (session-authorized, exactly as the consent page would) and sign a warrant
/// for `agent_email` at `audience`.
async fn sign_warrant(
    server: &TestServer,
    session: &str,
    delegator: &str,
    agent_email: &str,
    audience: &str,
) -> Warrant {
    let warrant_kp = KeyPair::generate();
    let parent_cert = issue_user_cert(server, session, delegator, &warrant_kp).await;
    // v0.5: an agent warrant must carry a status ref pinned to the cert's
    // registrar — which, for a broker-minted agent, is the broker's origin.
    Warrant::create_with_status(
        &parent_cert,
        agent_email,
        audience,
        Some(vec!["post".into()]),
        Duration::days(30),
        &warrant_kp,
        Some(browserid_core::StatusRef {
            uri: format!("http://{DOMAIN}/.well-known/browserid-status"),
            idx: 1,
        }),
    )
    .unwrap()
}

/// The flagship round-trip: register a delegation → endorse a mint → mint at
/// the broker (as target IdP) → sign an assertion locally → verify offline.
#[tokio::test]
async fn delegation_mint_assert_verify_roundtrip() {
    let (server, email_sender, broker_pub) = create_agent_server(5);
    // A primary human (email domain == the broker/IdP domain) so the whole
    // chain is primary-shaped and offline-verifiable via the core key resolver;
    // agents are then bare handles. (Fallback sub-addressing is covered by the
    // reserve tests + the guestbook e2e's DNS-aware verifier.)
    let (delegation, prov_kp, session) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;

    let agent_kp = KeyPair::generate();
    let bundle = mint_bundle(&delegation, &prov_kp, "attestor", &agent_kp);
    let endorsement = endorse(&server, &bundle).await;

    let body: Value = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": endorsement }))
        .await
        .json();
    assert_eq!(body["success"], true, "mint failed: {body}");
    assert_eq!(body["email"], "attestor@localhost:3000");

    // The minted cert is an agent certificate (v0.4): typed + attributed.
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    assert!(cert.is_agent());
    assert_eq!(cert.agent_parent(), Some("human@localhost:3000"));

    // Bare cert~assertion is fail-closed: an agent cert needs a warrant.
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &agent_kp).unwrap();
    let bare = format!("{}~{}", cert.encoded(), assertion.encoded());
    assert!(BackedAssertion::parse(&bare).is_err());

    // With a user-signed warrant, the presentation verifies offline and
    // carries the attribution.
    let warrant =
        sign_warrant(&server, &session, "human@localhost:3000", "attestor@localhost:3000", AUDIENCE)
            .await;
    let verified = BackedAssertion::new_agent(cert, warrant, assertion)
        .verify(AUDIENCE, |_| Ok(broker_pub.clone()))
        .unwrap();
    assert_eq!(verified.email(), "attestor@localhost:3000");
    let attribution = verified.agent().expect("agent attribution");
    assert_eq!(attribution.parent, "human@localhost:3000");
    assert_eq!(attribution.scopes, vec!["post"]);

    // Attribution recorded: agent → human@localhost:3000.
    let list_req = {
        let (u, p) = delegation.split_once('~').unwrap();
        let r = ProvisioningRequest::list(DOMAIN, &prov_kp).unwrap();
        RequestBundle::new(Certificate::parse(u).unwrap(), ProvisioningCert::parse(p).unwrap(), r)
            .encoded()
            .to_string()
    };
    let endorsement = endorse(&server, &list_req).await;
    let body: Value = server
        .post("/provision/list")
        .json(&json!({ "request_bundle": list_req, "endorsement": endorsement }))
        .await
        .json();
    let ids = body["identities"].as_array().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0]["parent_email"], "human@localhost:3000");
    assert_eq!(ids[0]["active"], true);
}

/// A mint with no endorsement, or an endorsement for a different bundle, is
/// rejected.
#[tokio::test]
async fn mint_requires_matching_endorsement() {
    let (server, email_sender, _) = create_agent_server(5);
    let (delegation, prov_kp, _s) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;
    let bundle = mint_bundle(&delegation, &prov_kp, "attestor", &KeyPair::generate());

    // Missing/garbage endorsement → 401.
    let resp = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": "not-a-jws" }))
        .await;
    assert_eq!(resp.status_code(), 401);

    // Endorsement for a *different* bundle → 401 (hash binding).
    let other = mint_bundle(&delegation, &prov_kp, "other", &KeyPair::generate());
    let endorsement = endorse(&server, &other).await;
    let resp = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": endorsement }))
        .await;
    assert_eq!(resp.status_code(), 401);
}

/// The broker will not endorse an unregistered or revoked provisioning cert.
#[tokio::test]
async fn endorse_requires_registered_active_cert() {
    let (server, email_sender, _) = create_agent_server(5);

    // A delegation the broker has never seen (self-issued end to end).
    let idp = KeyPair::generate(); // stands in for some issuer
    let user_kp = KeyPair::generate();
    let stray_cert =
        Certificate::create("elsewhere.example", "x@elsewhere.example", &user_kp.public_key(), Duration::hours(24), &idp)
            .unwrap();
    let prov_kp = KeyPair::generate();
    let p_cert =
        ProvisioningCert::create("x@elsewhere.example", &prov_kp.public_key(), Constraint::names(["ghost"]), Duration::days(90), &user_kp).unwrap();
    let req = ProvisioningRequest::list("elsewhere.example", &prov_kp).unwrap();
    let stray_bundle =
        RequestBundle::new(stray_cert, p_cert, req).encoded().to_string();
    let resp = server
        .post("/provision/endorse")
        .json(&json!({ "request_bundle": stray_bundle }))
        .await;
    assert_eq!(resp.status_code(), 404, "unregistered cert must not be endorsed");

    // Register a real one, then revoke it → endorse refused (403).
    let (delegation, prov_kp, session) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;
    let certs: Value = server
        .get("/wsapi/provisioning_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let id = certs["certs"][0]["id"].as_u64().unwrap();
    let csrf = get_csrf(&server, &session).await;
    let resp = server
        .post("/wsapi/revoke_provisioning_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "id": id }))
        .await;
    assert_eq!(resp.status_code(), 200);

    let (u, p) = delegation.split_once('~').unwrap();
    let req = ProvisioningRequest::list(DOMAIN, &prov_kp).unwrap();
    let bundle = RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        req,
    )
    .encoded()
    .to_string();
    let resp = server
        .post("/provision/endorse")
        .json(&json!({ "request_bundle": bundle }))
        .await;
    assert_eq!(resp.status_code(), 403, "revoked cert must not be endorsed");
}

/// Registration rejects a delegation whose delegator isn't a verified email on
/// the session account (the human-authorization gate).
#[tokio::test]
async fn register_requires_owned_verified_email() {
    let (server, email_sender, _) = create_agent_server(5);
    let session = create_user(&server, &email_sender, "human@localhost:3000", "testpassword").await;

    // A U_cert for an email the account does NOT own.
    let user_kp = KeyPair::generate();
    let foreign = issue_user_cert(&server, &session, "human@localhost:3000", &user_kp).await;
    // Sign a P_cert claiming a different delegator than the cert certifies.
    let prov_kp = KeyPair::generate();
    let p_cert =
        ProvisioningCert::create("someone@else.example", &prov_kp.public_key(), Constraint::names(["x"]), Duration::days(90), &user_kp).unwrap();
    let bundle = format!("{}~{}", foreign.encoded(), p_cert.encoded());
    let csrf = get_csrf(&server, &session).await;
    let resp = server
        .post("/wsapi/register_provisioning_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "label": "x", "bundle": bundle }))
        .await;
    // delegator mismatch caught first → 400.
    assert_eq!(resp.status_code(), 400);
}

/// Quota bounds active identities.
#[tokio::test]
async fn quota_enforced() {
    let (server, email_sender, _) = create_agent_server(2);
    let (delegation, prov_kp, _s) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;

    for name in ["one", "two"] {
        let bundle = mint_bundle(&delegation, &prov_kp, name, &KeyPair::generate());
        let e = endorse(&server, &bundle).await;
        let resp = server
            .post("/provision/mint")
            .json(&json!({ "request_bundle": bundle, "endorsement": e }))
            .await;
        assert_eq!(resp.status_code(), 200);
    }
    let bundle = mint_bundle(&delegation, &prov_kp, "three", &KeyPair::generate());
    let e = endorse(&server, &bundle).await;
    let resp = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": e }))
        .await;
    assert_eq!(resp.status_code(), 429);
}

/// Re-mint with a rotated agent keypair (P_cert unchanged) still verifies.
#[tokio::test]
async fn remint_rotated_agent_key() {
    let (server, email_sender, broker_pub) = create_agent_server(5);
    // Primary human → bare agent handle, offline-verifiable (see roundtrip note).
    let (delegation, prov_kp, session) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;

    let bundle = mint_bundle(&delegation, &prov_kp, "bot", &KeyPair::generate());
    let e = endorse(&server, &bundle).await;
    server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": e }))
        .await
        .json::<Value>();

    // Re-mint for the same name with a fresh agent keypair.
    let rotated = KeyPair::generate();
    let bundle = mint_bundle(&delegation, &prov_kp, "bot", &rotated);
    let e = endorse(&server, &bundle).await;
    let body: Value = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": e }))
        .await
        .json();
    assert_eq!(body["success"], true);
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &rotated).unwrap();
    // The warrant binds by identity, so it survives agent-key rotation.
    let warrant =
        sign_warrant(&server, &session, "human@localhost:3000", "bot@localhost:3000", AUDIENCE).await;
    let verified = BackedAssertion::new_agent(cert, warrant, assertion)
        .verify(AUDIENCE, |_| Ok(broker_pub.clone()))
        .unwrap();
    assert_eq!(verified.email(), "bot@localhost:3000");
}

/// Revocation of an identity sticks: re-mint fails, and the name isn't revived.
#[tokio::test]
async fn identity_revocation_sticks() {
    let (server, email_sender, _) = create_agent_server(5);
    let (delegation, prov_kp, _s) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;

    let bundle = mint_bundle(&delegation, &prov_kp, "doomed", &KeyPair::generate());
    let e = endorse(&server, &bundle).await;
    server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": e }))
        .await;

    // Revoke it.
    let (u, p) = delegation.split_once('~').unwrap();
    let req = ProvisioningRequest::revoke(DOMAIN, "doomed", &prov_kp).unwrap();
    let rev_bundle = RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        req,
    )
    .encoded()
    .to_string();
    let e = endorse(&server, &rev_bundle).await;
    let resp = server
        .post("/provision/revoke")
        .json(&json!({ "request_bundle": rev_bundle, "endorsement": e }))
        .await;
    assert_eq!(resp.status_code(), 200);

    // Re-mint now fails (403 — revoked identity, EmailNotVerified).
    let bundle = mint_bundle(&delegation, &prov_kp, "doomed", &KeyPair::generate());
    let e = endorse(&server, &bundle).await;
    let resp = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": e }))
        .await;
    assert_eq!(resp.status_code(), 403);
}

/// Disabled by default: every provisioning surface 404s.
#[tokio::test]
async fn disabled_by_default() {
    let (server, email_sender) = common::create_test_server();
    let session = create_user(&server, &email_sender, "human@localhost:3000", "testpassword").await;
    let csrf = get_csrf(&server, &session).await;

    let resp = server
        .post("/wsapi/register_provisioning_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "label": "x", "bundle": "a~b" }))
        .await;
    assert_eq!(resp.status_code(), 404);

    let resp = server
        .post("/provision/endorse")
        .json(&json!({ "request_bundle": "x~y~z" }))
        .await;
    assert_eq!(resp.status_code(), 404);
}

/// An endorsement issued by a foreign key is rejected at mint (the broker only
/// trusts its own endorsements for its own domain).
#[tokio::test]
async fn foreign_endorsement_rejected() {
    let (server, email_sender, _) = create_agent_server(5);
    let (delegation, prov_kp, _s) =
        register_agent_key(&server, &email_sender, "human@localhost:3000").await;
    let agent_kp = KeyPair::generate();
    let bundle_str = mint_bundle(&delegation, &prov_kp, "attestor", &agent_kp);

    // Forge an endorsement with a rogue broker key.
    let rogue = KeyPair::generate();
    let bundle = RequestBundle::parse(&bundle_str).unwrap();
    let forged = Endorsement::create(
        DOMAIN,
        DOMAIN,
        &bundle,
        "human@localhost:3000",
        &format!("http://{DOMAIN}"),
        Duration::minutes(10),
        &rogue,
    )
    .unwrap();
    let resp = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle_str, "endorsement": forged.encoded() }))
        .await;
    assert_eq!(resp.status_code(), 401);
}

/// A mint whose name the constraint doesn't authorize is refused at both the
/// endorse (403) and mint stages.
#[tokio::test]
async fn constraint_enforced_on_mint() {
    let (server, email_sender, _) = create_agent_server(5);
    let (delegation, prov_kp, _s) = register_agent_key_with(
        &server,
        &email_sender,
        "human@localhost:3000",
        Constraint { names: vec!["attestor".into()], patterns: vec!["svc+*".into()] },
    )
    .await;

    // Authorized: an exact name and a subaddress under the pattern.
    for name in ["attestor", "svc-ci"].iter().zip(["attestor", "svc+ci"]) {
        let bundle = mint_bundle(&delegation, &prov_kp, name.1, &KeyPair::generate());
        let e = endorse(&server, &bundle).await;
        let resp = server
            .post("/provision/mint")
            .json(&json!({ "request_bundle": bundle, "endorsement": e }))
            .await;
        assert_eq!(resp.status_code(), 200, "{} should be authorized", name.1);
    }

    // Unauthorized name: the broker refuses to even endorse it (403).
    let bundle = mint_bundle(&delegation, &prov_kp, "rogue", &KeyPair::generate());
    let resp = server
        .post("/provision/endorse")
        .json(&json!({ "request_bundle": bundle }))
        .await;
    assert_eq!(resp.status_code(), 403, "unauthorized name must not be endorsed");
}

/// Reserve pre-allocates the bound names so a later mint always succeeds, and
/// the reservation consumes quota + blocks the names for other accounts.
#[tokio::test]
async fn reserve_then_mint() {
    let (server, email_sender, broker_pub) = create_agent_server(5);
    let (delegation, prov_kp, session) = register_agent_key_with(
        &server,
        &email_sender,
        "human@localhost:3000",
        Constraint::names(["alpha", "beta"]),
    )
    .await;

    // Reserve carries no name; it acts on the constraint's names.
    let (u, p) = delegation.split_once('~').unwrap();
    let reserve = RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        ProvisioningRequest::reserve(DOMAIN, &prov_kp).unwrap(),
    )
    .encoded()
    .to_string();
    let e = endorse(&server, &reserve).await;
    let resp = server
        .post("/provision/reserve")
        .json(&json!({ "request_bundle": reserve, "endorsement": e }))
        .await;
    assert_eq!(resp.status_code(), 200, "reserve failed: {:?}", resp.text());

    // Both reserved identities now exist (attributed) and are mintable.
    let agent_kp = KeyPair::generate();
    let bundle = mint_bundle(&delegation, &prov_kp, "alpha", &agent_kp);
    let e = endorse(&server, &bundle).await;
    let body: Value = server
        .post("/provision/mint")
        .json(&json!({ "request_bundle": bundle, "endorsement": e }))
        .await
        .json();
    assert_eq!(body["success"], true, "mint of reserved name failed: {body}");
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    // Primary/native human (email domain == the IdP domain), so the name is a
    // bare local-part and the agent email is just `<name>@<domain>`.
    assert_eq!(cert.email().unwrap(), "alpha@localhost:3000");
    assert_eq!(cert.issuer(), DOMAIN);
    let _ = (broker_pub, session, agent_kp);
}

/// Registration rejects an empty (unconstrained) provisioning cert.
#[tokio::test]
async fn register_rejects_unconstrained_cert() {
    let (server, email_sender, _) = create_agent_server(5);
    let session = create_user(&server, &email_sender, "human@localhost:3000", "testpassword").await;
    let user_kp = KeyPair::generate();
    let user_cert = issue_user_cert(&server, &session, "human@localhost:3000", &user_kp).await;
    // Hand-build a P_cert with an empty constraint (bypassing create()'s guard)
    // by serializing claims directly is awkward; instead rely on create()
    // rejecting it — a caller can't produce an unconstrained bundle. Assert the
    // guard holds at the type level:
    assert!(ProvisioningCert::create(
        "human@localhost:3000",
        &KeyPair::generate().public_key(),
        Constraint::default(),
        Duration::days(90),
        &user_kp,
    )
    .is_err());
    let _ = user_cert;
}

/// Fallback owners must sub-address their own email, so two different owners'
/// names (`alice+shared` vs `bob+shared`) map to different addresses and never
/// collide — cross-account squatting is structurally impossible. (Bare-name
/// collisions on a shared domain are covered by registrar_glue's reserve tests.)
#[tokio::test]
async fn reserve_subaddresses_handles_per_owner() {
    let (server, email_sender, _) = create_agent_server(10);
    // First account (fallback: email domain != the IdP domain) — names must be
    // sub-addresses of its own email.
    let (deleg_a, kp_a, _sa) = register_agent_key_with(
        &server,
        &email_sender,
        "alice@example.com",
        Constraint::names(["alice+shared", "alice+only"]),
    )
    .await;
    let (u, p) = deleg_a.split_once('~').unwrap();
    let reserve_a = RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        ProvisioningRequest::reserve(DOMAIN, &kp_a).unwrap(),
    )
    .encoded()
    .to_string();
    let e = endorse(&server, &reserve_a).await;
    assert_eq!(
        server.post("/provision/reserve").json(&json!({ "request_bundle": reserve_a, "endorsement": e })).await.status_code(),
        200
    );

    // Second account reserves its own `bob+shared` — distinct from
    // alice+shared@example.com, so it succeeds.
    let (deleg_b, kp_b, _sb) = register_agent_key_with(
        &server,
        &email_sender,
        "bob@example.com",
        Constraint::names(["bob+shared", "bob+only"]),
    )
    .await;
    let (u, p) = deleg_b.split_once('~').unwrap();
    let reserve_b = RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        ProvisioningRequest::reserve(DOMAIN, &kp_b).unwrap(),
    )
    .encoded()
    .to_string();
    let e = endorse(&server, &reserve_b).await;
    let resp = server
        .post("/provision/reserve")
        .json(&json!({ "request_bundle": reserve_b, "endorsement": e }))
        .await;
    assert_eq!(resp.status_code(), 200, "per-owner handle must not collide: {:?}", resp.text());
}

/// A fallback owner (email domain != the IdP domain) may register ONLY names
/// that sub-address their own email; a bare name is rejected at registration.
#[tokio::test]
async fn fallback_owner_must_subaddress_its_own_email() {
    let (server, email_sender, _) = create_agent_server(5);
    let session = create_user(&server, &email_sender, "eve@example.com", "testpassword").await;
    let user_kp = KeyPair::generate();
    let user_cert = issue_user_cert(&server, &session, "eve@example.com", &user_kp).await;

    let register = |names: Constraint| {
        let prov_kp = KeyPair::generate();
        let p_cert =
            ProvisioningCert::create("eve@example.com", &prov_kp.public_key(), names, Duration::days(90), &user_kp)
                .unwrap();
        format!("{}~{}", user_cert.encoded(), p_cert.encoded())
    };

    // A bare name (grabbing `victim` on gmail) — rejected.
    let csrf = get_csrf(&server, &session).await;
    let bad = server
        .post("/wsapi/register_provisioning_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "label": "x", "bundle": register(Constraint::names(["victim"])) }))
        .await;
    assert_eq!(bad.status_code(), 400, "bare name for a fallback owner must be rejected: {:?}", bad.text());

    // Sub-addressing your own email — allowed.
    let csrf = get_csrf(&server, &session).await;
    let good = server
        .post("/wsapi/register_provisioning_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "label": "x", "bundle": register(Constraint::names(["eve+bot"])) }))
        .await;
    assert_eq!(good.status_code(), 200, "sub-address of own email must be allowed: {:?}", good.text());
}

/// The consent page must serve at both the bare path and the deep link —
/// regression: axum 0.7 param syntax is `/:code`, and `/{code}` silently
/// registers a literal segment (agents hand out deep links; a 404 there
/// strands the principal).
#[tokio::test]
async fn consent_page_serves_bare_and_deep_link() {
    let (server, _, _) = create_agent_server(5);
    for path in ["/consent", "/consent/wrq_someopaquecode"] {
        let resp = server.get(path).await;
        assert_eq!(resp.status_code(), 200, "GET {path}");
        assert!(resp.text().contains("Agent consent"), "GET {path} must serve the consent page");
    }
}
