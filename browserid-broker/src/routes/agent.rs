//! Delegation-chain agent provisioning — the broker's **target-IdP** role
//! (tdxf, spec v0.2), gated on `agent_provisioning_enabled`.
//!
//! For `@<broker-domain>` agent identities (whose parent is a broker-rooted/
//! fallback identity) this verifies the dual-signed request + endorsement and
//! mints (`POST /provision/{mint,reserve,list,revoke}`).
//!
//! The **registrar** role (provisioning-cert registry, endorsement signing,
//! warrant consent flow) lives in the extracted `browserid-registrar`
//! component (1pnf) — see `registrar_glue`. The broker runs both roles in
//! one process, so endorser and issuer are the same party here.
//!
//! Agent identities remain ordinary `EmailType::Agent` emails with a
//! `parent_email` attribution root; RPs verify the certs as plain browserid.
//! Revocation is soft: revoke the provisioning cert (registrar stops
//! endorsing) or the identity (mints fail), and outstanding certs age out
//! (≤24h).

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::provisioning::{Action, Endorsement, RequestBundle, VerifiedRequest};
use browserid_registrar::valid_agent_name;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, SessionStore, UserStore};

use super::cert::{issue_certificate, PublicKeyJson};

fn require_enabled<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
) -> Result<(), BrokerError> {
    if state.agent_provisioning_enabled {
        Ok(())
    } else {
        Err(BrokerError::AgentProvisioningDisabled)
    }
}

fn agent_pubkey_json(pk: &browserid_core::PublicKey) -> PublicKeyJson {
    PublicKeyJson {
        algorithm: "Ed25519".to_string(),
        public_key: pk.to_base64(),
    }
}

// ===========================================================================
// Broker-as-target-IdP: POST /provision/{mint,list,revoke}
// (for @<broker-domain> agent identities — fallback-rooted parents)
// ===========================================================================

/// SPIKE-A: reserved mint `name` that selects the human LOGIN mode (plain user
/// cert for the delegator's own identity) rather than agent minting. `@` is not
/// a legal agent-handle char, so it can never collide with a real handle.
pub const LOGIN_SELF: &str = "@self";

#[derive(Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[derive(Deserialize)]
pub struct ProvisionRequest {
    pub request_bundle: String,
    pub endorsement: String,
}

/// Verify a dual-signed provisioning request as the target IdP: full chain
/// against the broker's own key (we issued the U_cert), plus a fresh
/// broker-signed endorsement bound to this exact bundle. Returns the verified
/// request for the caller to act on.
fn verify_as_target_idp<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    req: &ProvisionRequest,
    expected_action: Action,
) -> Result<(RequestBundle, VerifiedRequest), BrokerError> {
    let bundle = RequestBundle::parse(&req.request_bundle)
        .map_err(|e| BrokerError::InvalidProvisioningRequest(e.to_string()))?;

    // The broker is the target IdP only for identities it roots. The U_cert
    // issuer must be our domain; then we verify the whole chain with our key.
    let verified = bundle
        .verify(&state.keypair.public_key())
        .map_err(|e| BrokerError::InvalidProvisioningRequest(e.to_string()))?;
    if verified.issuer != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest(format!(
            "identity is rooted at '{}', not this IdP",
            verified.issuer
        )));
    }
    if verified.request.domain != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request domain does not target this IdP".into(),
        ));
    }
    if verified.request.action != expected_action {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request action does not match this endpoint".into(),
        ));
    }

    // Endorsement: signed by us (broker == this IdP for its own domain), fresh,
    // bound to this exact bundle.
    let endorsement = Endorsement::parse(&req.endorsement)
        .map_err(|e| BrokerError::NotEndorsed(e.to_string()))?;
    endorsement
        .verify_for(&state.keypair.public_key(), &state.domain, &bundle)
        .map_err(|e| BrokerError::NotEndorsed(e.to_string()))?;

    Ok((bundle, verified))
}

#[derive(Serialize)]
pub struct MintResponse {
    pub success: bool,
    pub email: String,
    pub cert: String,
}

/// POST /provision/mint
pub async fn mint<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<MintResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::Mint)?;

    let name = verified
        .request
        .name
        .as_deref()
        .ok_or_else(|| BrokerError::InvalidProvisioningRequest("mint requires a name".into()))?;
    let agent_pub = verified
        .request
        .agent_key
        .as_ref()
        .ok_or_else(|| BrokerError::InvalidProvisioningRequest("mint requires an agent-key".into()))?;

    // SPIKE-A (DIRECTION A): the `@self` marker turns this same endpoint into
    // the human LOGIN path. Instead of an agent identity, we issue a plain user
    // cert binding the browser's key to the delegator's OWN verified email — the
    // authority is the delegation over the user's own identity (U_cert~P_cert),
    // established once in the interactive popup bootstrap. Structurally this
    // forces every IdP that does login to also serve /provision/mint.
    if name == LOGIN_SELF {
        if !verified.constraint.authorizes(LOGIN_SELF) {
            return Err(BrokerError::PolicyRefused(
                "credential is not login-capable (@self not in constraint)".into(),
            ));
        }
        // The delegator's own Email record — issue_certificate re-checks it is
        // verified and within the re-verification window (plain user cert path).
        let record = state
            .user_store
            .get_email(&verified.delegator)?
            .ok_or(BrokerError::EmailNotFound)?;
        let ephemeral = verified.request.ephemeral.unwrap_or(false);
        let cert = issue_certificate(
            &state.domain,
            &state.keypair,
            state.user_store.as_ref(),
            &record,
            &agent_pubkey_json(agent_pub),
            ephemeral,
        )?;
        tracing::info!(email = %record.email, "minted LOGIN cert via mint endpoint (@self)");
        return Ok(Json(MintResponse { success: true, email: record.email, cert }));
    }

    let record = ensure_agent_identity(&state, &verified, name)?;
    let ephemeral = verified.request.ephemeral.unwrap_or(false);
    let cert = issue_certificate(
        &state.domain,
        &state.keypair,
        state.user_store.as_ref(),
        &record,
        &agent_pubkey_json(agent_pub),
        ephemeral,
    )?;

    tracing::info!(email = %record.email, delegator = %verified.delegator, "minted agent identity (delegation chain)");
    Ok(Json(MintResponse {
        success: true,
        email: record.email,
        cert,
    }))
}

/// Ensure the agent identity `<name>@<domain>` exists for the delegator's
/// account, creating it (quota-checked) if new — used by both mint (then
/// issues a cert) and reserve (pre-allocates, no cert). Enforces that the
/// constraint authorizes `name` and that the name is a valid agent handle.
fn ensure_agent_identity<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    verified: &VerifiedRequest,
    name: &str,
) -> Result<crate::store::Email, BrokerError> {
    if !valid_agent_name(name) {
        return Err(BrokerError::ValidationError(
            "name must be 1-64 chars of [a-z0-9._+-], starting alphanumeric".into(),
        ));
    }
    if !verified.constraint.authorizes(name) {
        return Err(BrokerError::PolicyRefused(format!(
            "'{name}' is not authorized by this key's constraint"
        )));
    }

    let delegator = &verified.delegator;
    let account = state
        .user_store
        .get_user_by_email(delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;

    let email = browserid_registrar::agent_identity_email(delegator, name);
    match state.user_store.get_email(&email)? {
        Some(rec) if rec.user_id == account.id && rec.email_type == EmailType::Agent => {
            if !rec.verified {
                return Err(BrokerError::EmailNotVerified); // revoked; sticks
            }
            Ok(rec)
        }
        Some(_) => Err(BrokerError::EmailAlreadyExists),
        None => {
            let active = state
                .user_store
                .list_emails(account.id)?
                .iter()
                .filter(|e| e.email_type == EmailType::Agent && e.verified)
                .count();
            if active >= state.max_agent_identities_per_user {
                return Err(BrokerError::QuotaExceeded);
            }
            state
                .user_store
                .add_email_with_type(account.id, &email, true, EmailType::Agent)?;
            state.user_store.set_parent_email(&email, Some(delegator))?;
            state
                .user_store
                .get_email(&email)?
                .ok_or_else(|| BrokerError::Internal("identity vanished after insert".into()))
        }
    }
}

/// POST /provision/reserve — pre-allocate the cert's bound `names` so a later
/// mint can't be refused. Idempotent; consumes quota.
pub async fn reserve<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<SuccessResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::Reserve)?;
    // Reserve every bound name (all-or-nothing: any collision aborts before the
    // first insert, since we check availability up front).
    let names = verified.constraint.names.clone();
    let account = state
        .user_store
        .get_user_by_email(&verified.delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;
    // Collect every unavailable name (taken by another account or a non-agent
    // identity) so the user learns exactly which handles to change.
    let mut taken = Vec::new();
    for name in &names {
        let email = browserid_registrar::agent_identity_email(&verified.delegator, name);
        if let Some(rec) = state.user_store.get_email(&email)? {
            if rec.user_id != account.id || rec.email_type != EmailType::Agent {
                taken.push(name.clone());
            }
        }
    }
    if !taken.is_empty() {
        return Err(BrokerError::NamesTaken(taken));
    }
    for name in &names {
        ensure_agent_identity(&state, &verified, name)?;
    }
    tracing::info!(delegator = %verified.delegator, count = names.len(), "reserved agent identities");
    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Serialize)]
pub struct AgentIdentityInfo {
    pub email: String,
    pub parent_email: Option<String>,
    pub active: bool,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub success: bool,
    pub identities: Vec<AgentIdentityInfo>,
}

/// POST /provision/list
pub async fn list<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<ListResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::List)?;

    let account = state
        .user_store
        .get_user_by_email(&verified.delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;

    let identities = state
        .user_store
        .list_emails(account.id)?
        .into_iter()
        .filter(|e| e.email_type == EmailType::Agent)
        .map(|e| AgentIdentityInfo {
            email: e.email,
            parent_email: e.parent_email,
            active: e.verified,
            verified_at: e.verified_at,
        })
        .collect();

    Ok(Json(ListResponse { success: true, identities }))
}

/// POST /provision/revoke
pub async fn revoke<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<SuccessResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::Revoke)?;

    let name = verified
        .request
        .name
        .as_deref()
        .ok_or_else(|| BrokerError::InvalidProvisioningRequest("revoke requires a name".into()))?;
    let account = state
        .user_store
        .get_user_by_email(&verified.delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;
    let email = browserid_registrar::agent_identity_email(&verified.delegator, name);
    let record = state
        .user_store
        .get_email(&email)?
        .filter(|e| e.user_id == account.id && e.email_type == EmailType::Agent)
        .ok_or(BrokerError::EmailNotFound)?;

    state.user_store.unverify_email(&record.email)?;
    // Status bit (egr7): outstanding certs for this identity die at
    // status-checking verifiers within one cache window, not one TTL.
    state
        .user_store
        .set_status_revoked("identity", &record.email.to_lowercase())?;
    tracing::info!(email = %record.email, "revoked agent identity (delegation chain)");
    Ok(Json(SuccessResponse { success: true }))
}
