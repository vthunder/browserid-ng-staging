//! SPIKE-A (throwaway): "make the human's browser the first agent."
//!
//! Demonstrates the KEY MECHANIC of DIRECTION A: human LOGIN mints its cert
//! through the SAME provisioning/mint chain that agents use — a mode/parameter
//! difference, not a different transport. No hidden iframe, no cert-issuance
//! over postMessage.
//!
//! The model (shared across all three spikes):
//!   1. An interactive identity-proof (in a POPUP, first-party) bootstraps a
//!      PROVISIONING CREDENTIAL: the user's browser mints a U_cert for a
//!      freshly-generated browser identity key (`U_priv`), then `U_priv` signs
//!      a P_cert delegating a stable provisioning key (`P_priv`) — exactly the
//!      "agent credential" today's CLI holds.
//!   2. Thereafter the browser mints its LOGIN cert HEADLESSLY via the mint
//!      endpoint, signing a request with `P_priv`. The SAME endpoint, with a
//!      name, mints an AGENT (delegate) cert.
//!
//! This test reuses the real `browserid-core` provisioning types unchanged and
//! models the broker's `mint` handler branch (login vs agent) as a small free
//! function `mint_from_bundle`, mirroring the change sketched in
//! `browserid-broker/src/routes/agent.rs`.

use chrono::Duration;

use browserid_core::provisioning::{
    Action, Endorsement, ProvisioningRequest, ProvisioningRequestClaims, RequestBundle,
    VerifiedRequest,
};
use browserid_core::{Certificate, Constraint, KeyPair, ProvisioningCert};

const IDP_DOMAIN: &str = "mingo.place";
const BROKER_DOMAIN: &str = "mingo.place"; // broker == registrar == IdP in one process
const USER_EMAIL: &str = "dan@mingo.place";

/// The provisioning credential a browser holds after the popup bootstrap.
/// Identical in shape to what `browserid-agent`'s `AgentCredential` carries.
struct BrowserCredential {
    /// The stable provisioning key `P_priv` (never leaves the browser).
    provisioning_key: KeyPair,
    /// `U_cert ~ P_cert` — the delegation, minted+signed during the popup step.
    u_cert: Certificate,
    p_cert: ProvisioningCert,
}

/// STEP 1 — the interactive POPUP bootstrap, done once per browser.
///
/// In the real flow this all happens inside a first-party top-level popup on
/// the IdP origin (WinChan): the user authenticates (existing password/primary
/// login → a session cookie), the popup calls `/wsapi/cert_key` to mint a
/// `U_cert` for a fresh browser identity key, then signs the `P_cert`
/// delegation client-side. Here we simulate the IdP's `cert_key` issuance with
/// `idp_key` and do the client-side `P_cert` signing locally.
fn popup_bootstrap(idp_key: &KeyPair) -> BrowserCredential {
    // Fresh, per-browser identity key `U_priv` (non-extractable in the browser).
    let user_identity_key = KeyPair::generate();
    // The IdP, having authenticated the session, issues the browser a U_cert.
    let u_cert = Certificate::create(
        IDP_DOMAIN,
        USER_EMAIL,
        &user_identity_key.public_key(),
        Duration::hours(24),
        idp_key,
    )
    .unwrap();

    // The stable provisioning key the browser will mint with, forever.
    let provisioning_key = KeyPair::generate();

    // The delegation: U_priv signs "P_pub may provision on behalf of dan".
    // A login-capable constraint authorizes the user's own identity ("@self")
    // AND (optionally) agent handles. Agents get named handles; login uses the
    // reserved "@self" marker so the same credential does both.
    let constraint = Constraint::names(["@self", "bot"]);
    let p_cert = ProvisioningCert::create(
        USER_EMAIL,
        &provisioning_key.public_key(),
        constraint,
        Duration::days(90),
        &user_identity_key,
    )
    .unwrap();

    BrowserCredential { provisioning_key, u_cert, p_cert }
}

/// Assemble + endorse a bundle for a request, the way the browser/agent client
/// does headlessly (`browserid-agent::build_bundle` + `endorse`).
fn endorsed_bundle(
    cred: &BrowserCredential,
    request: ProvisioningRequest,
    broker_key: &KeyPair,
) -> (RequestBundle, Endorsement) {
    let bundle =
        RequestBundle::new(cred.u_cert.clone(), cred.p_cert.clone(), request);
    // The broker endorses exactly this bundle (registrar role).
    let endorsement = Endorsement::create(
        BROKER_DOMAIN,
        IDP_DOMAIN,
        &bundle,
        USER_EMAIL,
        BROKER_DOMAIN,
        Duration::minutes(10),
        broker_key,
    )
    .unwrap();
    (bundle, endorsement)
}

/// The `@self` login marker: a request whose `name` is `@self` mints a plain
/// user (login) cert for the delegator's OWN identity instead of an agent.
const LOGIN_SELF: &str = "@self";

/// MODELS THE BROKER'S `mint` HANDLER (see agent.rs::mint). One endpoint, two
/// modes, chosen by the request `name`:
///   * `name == "@self"`  → LOGIN: a plain user cert binding the browser key to
///                          the delegator's own email. Authority = the
///                          delegation over the user's own identity.
///   * any other `name`   → AGENT: an agent cert `name@domain` attributed to
///                          the delegator (today's behaviour).
/// Both share verification (`verify_as_target_idp`) and issuance mechanics.
fn mint_from_bundle(
    idp_key: &KeyPair,
    broker_key: &KeyPair,
    bundle: &RequestBundle,
    endorsement: &Endorsement,
) -> Certificate {
    // --- verify_as_target_idp: full user-side chain under the IdP's key ---
    let verified: VerifiedRequest = bundle.verify(&idp_key.public_key()).unwrap();
    assert_eq!(verified.issuer, IDP_DOMAIN, "U_cert rooted at this IdP");
    assert_eq!(verified.request.domain, IDP_DOMAIN, "audience pinned");
    assert_eq!(verified.request.action, Action::Mint);
    // Fresh broker endorsement bound to this exact bundle.
    endorsement
        .verify_for(&broker_key.public_key(), IDP_DOMAIN, bundle)
        .unwrap();

    let name = verified.request.name.as_deref().expect("mint requires a name");
    let agent_pub = verified.request.agent_key.as_ref().expect("mint requires agent-key");

    if name == LOGIN_SELF {
        // LOGIN MODE. The delegation already proves the user authorized this
        // browser key to act as them; issue a plain user cert for the
        // delegator's OWN email. (The broker would additionally load the
        // delegator's Email record and run the standard verified/re-verify
        // check via `issue_certificate`.)
        assert!(
            verified.constraint.authorizes(LOGIN_SELF),
            "credential must be login-capable (@self in constraint)"
        );
        Certificate::create(
            IDP_DOMAIN,
            &verified.delegator,
            agent_pub,
            Duration::hours(24),
            idp_key,
        )
        .unwrap()
    } else {
        // AGENT MODE — today's path: ensure `<name>@domain` agent identity and
        // stamp an agent cert attributed to the delegator.
        assert!(verified.constraint.authorizes(name), "constraint authorizes name");
        let agent_email = format!("{name}@{IDP_DOMAIN}");
        Certificate::create_agent(
            IDP_DOMAIN,
            &agent_email,
            &verified.delegator,
            agent_pub,
            Duration::hours(24),
            idp_key,
            Some(format!("https://{BROKER_DOMAIN}")),
        )
        .unwrap()
    }
}

/// A login/mint request signed by the browser's stable provisioning key.
fn login_request(cred: &BrowserCredential, browser_login_pub: &KeyPair) -> ProvisioningRequest {
    ProvisioningRequest::mint(
        IDP_DOMAIN,
        LOGIN_SELF,
        &browser_login_pub.public_key(),
        false,
        &cred.provisioning_key,
    )
    .unwrap()
}

/// An agent/mint request for a named delegate — the SAME endpoint, same key.
fn agent_request(cred: &BrowserCredential, agent_pub: &KeyPair) -> ProvisioningRequest {
    ProvisioningRequest::mint(
        IDP_DOMAIN,
        "bot",
        &agent_pub.public_key(),
        false,
        &cred.provisioning_key,
    )
    .unwrap()
}

#[test]
fn login_and_agent_come_from_the_same_mint_endpoint() {
    let idp_key = KeyPair::generate();
    let broker_key = &idp_key; // broker == IdP in one process (as in the broker)

    // === STEP 1: interactive popup bootstrap (once) ===
    let cred = popup_bootstrap(&idp_key);

    // === STEP 2a: headless LOGIN mint ===
    // The browser's per-login cert key (could be the same as P or fresh).
    let browser_login_key = KeyPair::generate();
    let (login_bundle, login_end) =
        endorsed_bundle(&cred, login_request(&cred, &browser_login_key), broker_key);
    let login_cert = mint_from_bundle(&idp_key, broker_key, &login_bundle, &login_end);

    // It is a PLAIN USER (login) cert for the human's real email.
    login_cert.verify(&idp_key.public_key()).unwrap();
    assert_eq!(login_cert.email(), Some(USER_EMAIL));
    assert!(!login_cert.is_agent(), "login cert is a plain user cert, not an agent cert");
    assert_eq!(login_cert.public_key(), &browser_login_key.public_key());

    // === STEP 2b: headless AGENT mint — SAME endpoint, name param differs ===
    let agent_key = KeyPair::generate();
    let (agent_bundle, agent_end) =
        endorsed_bundle(&cred, agent_request(&cred, &agent_key), broker_key);
    let agent_cert = mint_from_bundle(&idp_key, broker_key, &agent_bundle, &agent_end);

    // It is an AGENT cert `bot@domain` attributed to the human.
    agent_cert.verify(&idp_key.public_key()).unwrap();
    assert_eq!(agent_cert.email(), Some("bot@mingo.place"));
    assert!(agent_cert.is_agent(), "named mint yields an agent cert");
    assert_eq!(agent_cert.public_key(), &agent_key.public_key());

    // THE POINT: login and agent are the same verb through the same door.
}

#[test]
fn login_cert_re_mints_headlessly_after_bootstrap() {
    // ITP-relevance: after the ONE interactive popup, the browser holds a
    // stable P_priv + U_cert~P_cert and re-mints login certs with NO further
    // top-level navigation and NO third-party cookie — pure HTTP POST.
    let idp_key = KeyPair::generate();
    let cred = popup_bootstrap(&idp_key);

    for _ in 0..3 {
        let k = KeyPair::generate();
        let (b, e) = endorsed_bundle(&cred, login_request(&cred, &k), &idp_key);
        let cert = mint_from_bundle(&idp_key, &idp_key, &b, &e);
        assert_eq!(cert.email(), Some(USER_EMAIL));
        assert!(!cert.is_agent());
    }
}

#[test]
fn a_login_only_credential_cannot_mint_arbitrary_agents() {
    // A credential whose constraint only grants "@self" can log the user in but
    // cannot mint a `bot` agent — the constraint gate still holds. (Shows the
    // modes are independently authorized, not an all-or-nothing escalation.)
    let idp_key = KeyPair::generate();
    let user_identity_key = KeyPair::generate();
    let u_cert = Certificate::create(
        IDP_DOMAIN,
        USER_EMAIL,
        &user_identity_key.public_key(),
        Duration::hours(24),
        &idp_key,
    )
    .unwrap();
    let provisioning_key = KeyPair::generate();
    let p_cert = ProvisioningCert::create(
        USER_EMAIL,
        &provisioning_key.public_key(),
        Constraint::names(["@self"]), // login only
        Duration::days(90),
        &user_identity_key,
    )
    .unwrap();
    let cred = BrowserCredential { provisioning_key, u_cert, p_cert };

    // Login works.
    let k = KeyPair::generate();
    let (b, e) = endorsed_bundle(&cred, login_request(&cred, &k), &idp_key);
    let cert = mint_from_bundle(&idp_key, &idp_key, &b, &e);
    assert_eq!(cert.email(), Some(USER_EMAIL));

    // But a named agent mint is not authorized by this constraint.
    let verified = {
        let req = agent_request(&cred, &KeyPair::generate());
        RequestBundle::new(cred.u_cert.clone(), cred.p_cert.clone(), req)
            .verify(&idp_key.public_key())
            .unwrap()
    };
    assert!(!verified.constraint.authorizes("bot"));
}

// Suppress unused-field warning for the doc-only `ProvisioningRequestClaims`
// import kept for reference in the module docs.
#[allow(dead_code)]
fn _doc_ref(_: ProvisioningRequestClaims) {}
