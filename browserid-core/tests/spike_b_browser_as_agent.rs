//! SPIKE-B (throwaway): "make the human's browser the first agent" via a
//! TOP-LEVEL REDIRECT bootstrap + HEADLESS HTTP mint.
//!
//! This test demonstrates the KEY MECHANIC end-to-end at the crypto layer,
//! using only the existing delegation-chain machinery in `browserid-core`
//! (the same types `browserid-agent` and the broker already use):
//!
//!   1. A user, in-browser, delegates their STABLE BROWSER KEY as a
//!      provisioning key — signing a `P_cert` with their non-extractable
//!      identity key (exactly what `account.html` already does today, lines
//!      706-713). The `U_cert~P_cert` pair is the PROVISIONING CREDENTIAL.
//!      In Direction B this pair is what the redirect returns (see report).
//!
//!   2. The browser then mints HEADLESSLY over HTTP through ONE endpoint,
//!      choosing by a single parameter (`Action`):
//!        - `Action::Login` -> a plain USER (login) cert for the user's OWN
//!          identity, bound to the browser's stable key;
//!        - `Action::Mint`  -> an AGENT (delegate) cert for a derived handle.
//!
//! The point: login and agent-minting are THE SAME operation over THE SAME
//! credential and endpoint, differing only by a parameter — so login
//! structurally implies agent capability.
//!
//! We model the broker/IdP's `verify_as_target_idp` + `issue_certificate`
//! branch (broker crate, not depended on here) with the public core APIs it
//! is built from, to keep this test self-contained and runnable.

use chrono::Duration;

use browserid_core::provisioning::{
    Action, Constraint, ProvisioningCert, ProvisioningRequest, RequestBundle,
    PROVISIONING_CERT_VALIDITY_DAYS,
};
use browserid_core::{Certificate, KeyPair, PublicKey};

const IDP_DOMAIN: &str = "mingo.place";
const USER_EMAIL: &str = "dan@mingo.place";

/// The browser's persistent state after the redirect bootstrap: its stable
/// key + the provisioning credential (delegation) authorizing that key.
struct ProvisionedBrowser {
    /// The browser's STABLE key — the "first agent" key. In the real browser
    /// this is the non-extractable WebCrypto key in IndexedDB (keystore.js).
    browser_key: KeyPair,
    /// P_priv — signs provisioning requests. In-browser this is the
    /// extractable provisioning key the credential carries.
    provisioning_key: KeyPair,
    /// U_cert~P_cert — returned by the redirect bootstrap (see report §2).
    delegation: String,
}

/// Step 1: reproduce the in-browser delegation `account.html` performs, i.e.
/// what the Direction-B redirect must return. The user's identity key (which
/// the IdP certified in `u_cert`) signs a P_cert delegating the provisioning
/// key. A login-capable credential also authorizes the user's own identity
/// (modeled here by a `login` marker in the constraint's names).
fn bootstrap_via_redirect(idp: &KeyPair) -> ProvisionedBrowser {
    let identity_key = KeyPair::generate(); // the user's non-extractable identity key
    let browser_key = KeyPair::generate(); // the stable browser (login) key
    let provisioning_key = KeyPair::generate();

    // The IdP certified the user's identity key during the interactive login
    // (the full-page redirect). Short-lived, as always.
    let u_cert = Certificate::create(
        IDP_DOMAIN,
        USER_EMAIL,
        &identity_key.public_key(),
        Duration::hours(24),
        idp,
    )
    .unwrap();

    // The browser signs the delegation with the identity key. The constraint
    // both reserves an agent handle ("ci") AND authorizes login (the sentinel
    // "@self" — a name no agent handle can be, since agent names are
    // [a-z0-9._+-] with no '@'). This keeps the login capability EXPLICIT in
    // the signed credential rather than implicit.
    let p_cert = ProvisioningCert::create(
        USER_EMAIL,
        &provisioning_key.public_key(),
        Constraint::names(["ci", "@self"]),
        Duration::days(PROVISIONING_CERT_VALIDITY_DAYS),
        &identity_key,
    )
    .unwrap();

    let delegation = format!("{}~{}", u_cert.encoded(), p_cert.encoded());
    ProvisionedBrowser { browser_key, provisioning_key, delegation }
}

/// Build `U_cert~P_cert~R` from the credential + a request (identical to
/// `browserid_agent::build_bundle`).
fn build_bundle(delegation: &str, request: ProvisioningRequest) -> RequestBundle {
    let (u, p) = delegation.split_once('~').unwrap();
    RequestBundle::new(
        Certificate::parse(u).unwrap(),
        ProvisioningCert::parse(p).unwrap(),
        request,
    )
}

/// Model of the broker/IdP mint handler: verify the chain against the IdP key
/// (exactly `RequestBundle::verify`, as `agent::verify_as_target_idp` does),
/// then branch issuance on the request action — the ONE parameter that
/// decides user-cert vs agent-cert. Returns the minted cert.
fn idp_mint(idp: &KeyPair, bundle: &RequestBundle) -> Result<Certificate, String> {
    let verified = bundle.verify(&idp.public_key()).map_err(|e| e.to_string())?;
    let agent_key: &PublicKey = verified
        .request
        .agent_key
        .as_ref()
        .ok_or("mint/login requires an agent-key")?;

    match verified.request.action {
        // LOGIN: plain user cert for the delegator's OWN identity, bound to
        // the browser's stable key. Authorization: the credential must
        // explicitly carry the "@self" login capability.
        Action::Login => {
            if !verified.constraint.authorizes("@self") {
                return Err("credential is not authorized for login".into());
            }
            Ok(Certificate::create(
                IDP_DOMAIN,
                &verified.delegator, // the user's own email — NOT a derived name
                agent_key,
                Duration::hours(24),
                idp,
            )
            .unwrap())
        }
        // MINT: agent cert for a derived, constraint-authorized handle.
        Action::Mint => {
            let name = verified.request.name.as_deref().ok_or("mint requires a name")?;
            if !verified.constraint.authorizes(name) {
                return Err(format!("'{name}' not authorized by constraint"));
            }
            let email = format!("{name}@{IDP_DOMAIN}");
            Ok(Certificate::create_agent(
                IDP_DOMAIN,
                &email,
                &verified.delegator, // agent.parent attribution
                agent_key,
                Duration::hours(24),
                idp,
                Some("https://browserid.me".to_string()),
            )
            .unwrap())
        }
        other => Err(format!("endpoint does not handle {other:?}")),
    }
}

#[test]
fn same_endpoint_mints_login_cert_and_agent_cert_by_parameter() {
    let idp = KeyPair::generate();
    let browser = bootstrap_via_redirect(&idp);

    // --- LOGIN: the browser mints its own login cert, headlessly ---
    let login_req = ProvisioningRequest::login(
        IDP_DOMAIN,
        &browser.browser_key.public_key(),
        false,
        &browser.provisioning_key,
    )
    .unwrap();
    let login_bundle = build_bundle(&browser.delegation, login_req);
    let login_cert = idp_mint(&idp, &login_bundle).expect("login mint");

    // It is a PLAIN user cert for the user's OWN identity, bound to the stable
    // browser key. This is a first-class login credential.
    assert!(!login_cert.is_agent(), "login cert must be a plain user cert");
    assert_eq!(login_cert.email(), Some(USER_EMAIL));
    assert_eq!(login_cert.public_key(), &browser.browser_key.public_key());
    // And it verifies under the IdP's published key like any browserid cert —
    // an RP needs no new machinery.
    login_cert.verify(&idp.public_key()).expect("login cert verifies");

    // --- AGENT: the SAME credential + SAME endpoint mints a delegate ---
    let agent_key = KeyPair::generate();
    let agent_req =
        ProvisioningRequest::mint(IDP_DOMAIN, "ci", &agent_key.public_key(), false, &browser.provisioning_key)
            .unwrap();
    let agent_bundle = build_bundle(&browser.delegation, agent_req);
    let agent_cert = idp_mint(&idp, &agent_bundle).expect("agent mint");

    assert!(agent_cert.is_agent(), "agent cert must be an agent cert");
    assert_eq!(agent_cert.email(), Some("ci@mingo.place"));
    assert_eq!(agent_cert.agent_parent(), Some(USER_EMAIL));
    agent_cert.verify(&idp.public_key()).expect("agent cert verifies");
}

#[test]
fn login_refused_without_the_login_capability() {
    // A credential that only reserves an agent handle (no "@self") cannot be
    // used to mint a login cert — provisioning-for-agents does not silently
    // grant login-as-the-user.
    let idp = KeyPair::generate();
    let identity_key = KeyPair::generate();
    let browser_key = KeyPair::generate();
    let provisioning_key = KeyPair::generate();
    let u_cert =
        Certificate::create(IDP_DOMAIN, USER_EMAIL, &identity_key.public_key(), Duration::hours(24), &idp)
            .unwrap();
    let p_cert = ProvisioningCert::create(
        USER_EMAIL,
        &provisioning_key.public_key(),
        Constraint::names(["ci"]), // agent-only, NOT login-capable
        Duration::days(PROVISIONING_CERT_VALIDITY_DAYS),
        &identity_key,
    )
    .unwrap();
    let delegation = format!("{}~{}", u_cert.encoded(), p_cert.encoded());

    let login_req =
        ProvisioningRequest::login(IDP_DOMAIN, &browser_key.public_key(), false, &provisioning_key).unwrap();
    let bundle = build_bundle(&delegation, login_req);
    let err = idp_mint(&idp, &bundle).unwrap_err();
    assert!(err.contains("not authorized for login"), "{err}");
}

#[test]
fn login_request_is_domain_pinned_and_chain_bound() {
    // The login request is the same short-lived, audience-pinned, P_priv-signed
    // shape as every other request: a request for another IdP, or signed by a
    // key the credential didn't delegate, is refused by the same verify path.
    let idp = KeyPair::generate();
    let browser = bootstrap_via_redirect(&idp);

    // Wrong signer (not P_priv) → chain verification fails.
    let rogue = KeyPair::generate();
    let bad = build_bundle(
        &browser.delegation,
        ProvisioningRequest::login(IDP_DOMAIN, &browser.browser_key.public_key(), false, &rogue).unwrap(),
    );
    assert!(bad.verify(&idp.public_key()).is_err(), "rogue-signed login must fail the chain");

    // Wrong issuer key (a different IdP's key) → U_cert signature fails.
    let other_idp = KeyPair::generate();
    let good = build_bundle(
        &browser.delegation,
        ProvisioningRequest::login(IDP_DOMAIN, &browser.browser_key.public_key(), false, &browser.provisioning_key)
            .unwrap(),
    );
    assert!(good.verify(&other_idp.public_key()).is_err(), "login must not verify under a foreign IdP key");
}
