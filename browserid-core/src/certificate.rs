//! Identity certificates for BrowserID-NG
//!
//! A certificate binds a user's public key to their email address,
//! signed by the email domain's key.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::status::StatusRef;
use crate::{Error, KeyPair, PublicKey, Result};

/// Claim-level `typ` of an agent certificate (spec §5.1). A plain user
/// certificate carries no claim-level `typ`; a verifier MUST reject any
/// certificate whose `typ` it does not recognize (core §4.1/§6.2), which is
/// what makes agent credentials fail-closed at verifiers that predate them.
pub const TYP_AGENT_CERT: &str = "browserid-agent-cert-v1";

/// Claim-level `typ` of a **self-derived agent certificate** (self-derivation
/// design §3.1). A base identity `user@domain` — holding its domain-signed base
/// cert and matching key — self-signs this cert with its own identity key
/// rather than the domain key. The distinct `typ` makes a verifier select the
/// constrained self-derivation path, and makes verifiers that predate this
/// feature **fail closed** (the [`Certificate::parse`] matcher rejects any
/// `typ` it does not recognize).
pub const TYP_SELF_AGENT_CERT: &str = "browserid-self-agent-cert-v1";

/// The universal `authority` claim carried by every certificate
/// (self-derivation design §3.2 / decision E.2). It answers **what the cert
/// grants**, explicitly and on every cert type — never inferred from `typ`:
///
/// - [`Authority::Open`] — identity / login certs (base identity, plain user,
///   regular subaddress): full authority **as the principal**.
/// - [`Authority::Closed`] — agent certs: authority is **warrant-defined**; an
///   RP SHOULD consult the accompanying warrant's scopes, not the principal
///   alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Authority {
    /// Full authority as the principal (identity / login certs).
    #[serde(rename = "open")]
    Open,
    /// Warrant-defined authority (agent certs).
    #[serde(rename = "closed")]
    Closed,
}

/// The `agent` claims block on an agent certificate: issuer-set attribution.
/// Presence of this block (with [`TYP_AGENT_CERT`]) is what makes an identity
/// protocol-visible as an agent. The agent's handle is the local part of the
/// certificate's `principal.email`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentClaims {
    /// The delegator this agent acts for — set by the IdP from the verified
    /// provisioning chain, never by the agent.
    pub parent: String,
}

/// Principal identifier in a certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Principal {
    /// Email address principal
    Email {
        email: String,
    },
}

impl Principal {
    /// Create an email principal
    pub fn email(email: impl Into<String>) -> Self {
        Principal::Email { email: email.into() }
    }

    /// Get the email address if this is an email principal
    pub fn as_email(&self) -> Option<&str> {
        match self {
            Principal::Email { email } => Some(email),
        }
    }

    /// Extract the domain from an email principal
    pub fn domain(&self) -> Option<&str> {
        self.as_email().and_then(|e| e.split('@').nth(1))
    }
}

/// Claims in an identity certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateClaims {
    /// Claim-level type. Absent on a plain user certificate; [`TYP_AGENT_CERT`]
    /// on an agent certificate. Any other value is rejected at parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Issuer (the domain that signed this certificate)
    pub iss: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// The user's public key
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,

    /// The principal (email address)
    pub principal: Principal,

    /// Agent attribution block — present iff `typ` is [`TYP_AGENT_CERT`] or
    /// [`TYP_SELF_AGENT_CERT`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentClaims>,

    /// Universal authority declaration (self-derivation design §3.2). Set by
    /// every constructor: identity/base = [`Authority::Open`], agent =
    /// [`Authority::Closed`]. `None` only on certificates minted before this
    /// field existed (parsed for backward compatibility); the self-derivation
    /// verifier requires it to be present and `closed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<Authority>,

    /// Agent spec §5.1: the origin of the registrar the delegator's broker
    /// chose — where the agent raises consent requests and where its warrant
    /// status list is published. Set by the IdP from the endorsement, never
    /// by the agent. An RP pins each warrant's revocation authority to this
    /// value (§5.3), which rejects any agent warrant whose cert lacks it.
    /// Present only on agent certificates; `None` on plain user certs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,

    /// Fast-revocation hook (core §6.4): where this credential's status bit
    /// lives. Issuers allocate one index per *identity*, so revoking an
    /// identity kills every outstanding cert for it at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
}

/// An identity certificate binding a public key to an email address
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The encoded JWT
    encoded: String,
    /// The decoded claims
    claims: CertificateClaims,
}

impl Certificate {
    /// Create and sign a new certificate
    ///
    /// # Arguments
    /// * `issuer` - The domain issuing this certificate
    /// * `email` - The user's email address
    /// * `user_public_key` - The user's public key to certify
    /// * `validity` - How long the certificate should be valid
    /// * `issuer_key` - The domain's signing key
    pub fn create(
        issuer: &str,
        email: &str,
        user_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
    ) -> Result<Self> {
        Self::create_with_status(issuer, email, user_public_key, validity, issuer_key, None)
    }

    /// [`Certificate::create`] with a status-list reference (core §6.4)
    pub fn create_with_status(
        issuer: &str,
        email: &str,
        user_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        let now = Utc::now();
        let exp = now + validity;

        let claims = CertificateClaims {
            typ: None,
            iss: issuer.to_string(),
            exp: exp.timestamp(),
            iat: Some(now.timestamp()),
            public_key: user_public_key.clone(),
            principal: Principal::email(email),
            agent: None,
            authority: Some(Authority::Open),
            registrar: None,
            status,
        };

        let encoded = Self::encode_and_sign(&claims, issuer_key)?;

        Ok(Self { encoded, claims })
    }

    /// Create and sign an **agent certificate** (spec §5.1): a user
    /// certificate carrying `typ` [`TYP_AGENT_CERT`] and an `agent` block
    /// attributing it to `parent` (the delegator, from the verified
    /// provisioning chain).
    pub fn create_agent(
        issuer: &str,
        agent_email: &str,
        parent: &str,
        agent_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
        registrar: Option<String>,
    ) -> Result<Self> {
        Self::create_agent_with_status(
            issuer, agent_email, parent, agent_public_key, validity, issuer_key, registrar, None,
        )
    }

    /// [`Certificate::create_agent`] with a status-list reference (core §6.4)
    pub fn create_agent_with_status(
        issuer: &str,
        agent_email: &str,
        parent: &str,
        agent_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
        registrar: Option<String>,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        let now = Utc::now();
        let claims = CertificateClaims {
            typ: Some(TYP_AGENT_CERT.to_string()),
            iss: issuer.to_string(),
            exp: (now + validity).timestamp(),
            iat: Some(now.timestamp()),
            public_key: agent_public_key.clone(),
            principal: Principal::email(agent_email),
            agent: Some(AgentClaims {
                parent: parent.to_string(),
            }),
            authority: Some(Authority::Closed),
            registrar,
            status,
        };

        let encoded = Self::encode_and_sign(&claims, issuer_key)?;

        Ok(Self { encoded, claims })
    }

    /// Create and sign a **self-derived agent certificate** (self-derivation
    /// design §3.4, phase-1 agent-as-self case). The base identity `user@domain`
    /// — holding its domain-signed `base_cert` and matching `base_key` —
    /// self-signs an agent cert whose principal **equals** the base principal.
    ///
    /// Unlike [`Certificate::create_agent`], this is signed by the **base
    /// identity key**, not the domain key: `iss` is the base identity's email
    /// (decision D, self-issuance), `typ` is [`TYP_SELF_AGENT_CERT`],
    /// `authority` is [`Authority::Closed`], `agent.parent` is the base identity,
    /// and a `status` ref is mandatory (§3.3).
    ///
    /// The derived validity is bound to the base cert's: `exp` is the earlier of
    /// `now + validity` and the base cert's `exp` (decision OQ-3 — a self-derived
    /// agent cert can never outlive the short-lived base cert it chains to).
    pub fn create_self_derived_agent(
        base_cert: &Certificate,
        agent_public_key: &PublicKey,
        base_key: &KeyPair,
        validity: Duration,
        status: StatusRef,
    ) -> Result<Self> {
        let base_email = base_cert
            .email()
            .ok_or_else(|| Error::InvalidCertificate("base cert has no email principal".into()))?;

        // The base must itself be a plain identity cert — an agent cert cannot be
        // a self-derivation base (it has no full authority to delegate).
        if base_cert.is_any_agent() {
            return Err(Error::InvalidCertificate(
                "self-derivation base must be a plain identity certificate".into(),
            ));
        }

        // Phase-1 agent-as-self: the derived principal equals the base principal.
        // The name-constraint check is written for the general form (also
        // accepting `base+label@domain`) so phase 2 can reuse it unchanged.
        let derived_email = base_email.to_string();
        if !derived_name_matches(base_email, &derived_email) {
            return Err(Error::InvalidCertificate(
                "self-derived principal violates the name constraint".into(),
            ));
        }

        let now = Utc::now();
        // Bind the derived validity to the base cert (OQ-3).
        let exp = (now + validity).timestamp().min(base_cert.claims().exp);

        let claims = CertificateClaims {
            typ: Some(TYP_SELF_AGENT_CERT.to_string()),
            iss: base_email.to_string(),
            exp,
            iat: Some(now.timestamp()),
            public_key: agent_public_key.clone(),
            principal: Principal::email(derived_email),
            agent: Some(AgentClaims {
                parent: base_email.to_string(),
            }),
            authority: Some(Authority::Closed),
            registrar: None,
            status: Some(status),
        };

        let encoded = Self::encode_and_sign(&claims, base_key)?;

        Ok(Self { encoded, claims })
    }

    /// The status-list reference, if this credential carries one
    pub fn status(&self) -> Option<&StatusRef> {
        self.claims.status.as_ref()
    }

    /// This certificate's declared authority model (§3.2), if present.
    pub fn authority(&self) -> Option<Authority> {
        self.claims.authority
    }

    /// Whether this is a **self-derived** agent certificate (`typ` ==
    /// [`TYP_SELF_AGENT_CERT`]).
    pub fn is_self_agent(&self) -> bool {
        self.claims.typ.as_deref() == Some(TYP_SELF_AGENT_CERT)
    }

    /// Whether this certificate is an agent of any kind — a domain-issued agent
    /// ([`Certificate::is_agent`]) **or** a self-derived agent
    /// ([`Certificate::is_self_agent`]). This is the predicate that governs
    /// "requires a warrant" and "cannot be the base/parent of a delegation".
    pub fn is_any_agent(&self) -> bool {
        self.is_agent() || self.is_self_agent()
    }

    /// Parse a certificate from its encoded form (does not verify signature).
    ///
    /// Fail-closed on type (core §4.1): a plain certificate carries no
    /// claim-level `typ` and no `agent` block; an agent certificate carries
    /// both. Any other combination — an unrecognized `typ`, a `typ` without
    /// its block, or an `agent` block on an untyped certificate — is
    /// rejected.
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims = Self::decode_claims(encoded)?;
        match (claims.typ.as_deref(), claims.agent.is_some()) {
            (None, false) => {}
            (Some(TYP_AGENT_CERT), true) => {}
            (Some(TYP_SELF_AGENT_CERT), true) => {}
            (Some(TYP_AGENT_CERT | TYP_SELF_AGENT_CERT), false) => {
                return Err(Error::InvalidCertificate(
                    "agent certificate missing its agent block".into(),
                ));
            }
            (Some(typ), _) => {
                return Err(Error::InvalidCertificate(format!(
                    "unrecognized certificate typ '{typ}'"
                )));
            }
            (None, true) => {
                return Err(Error::InvalidCertificate(
                    "agent block on a certificate without the agent typ".into(),
                ));
            }
        }
        Ok(Self {
            encoded: encoded.to_string(),
            claims,
        })
    }

    /// Whether this is an agent certificate (`typ` == [`TYP_AGENT_CERT`])
    pub fn is_agent(&self) -> bool {
        self.claims.typ.as_deref() == Some(TYP_AGENT_CERT)
    }

    /// The delegator this agent certificate is attributed to, if any
    pub fn registrar(&self) -> Option<&str> {
        self.claims.registrar.as_deref()
    }

    pub fn agent_parent(&self) -> Option<&str> {
        self.claims.agent.as_ref().map(|a| a.parent.as_str())
    }

    /// Verify the certificate signature against a public key
    pub fn verify(&self, issuer_public_key: &PublicKey) -> Result<()> {
        Self::verify_signature(&self.encoded, issuer_public_key)
    }

    /// Check if the certificate has expired (relative to now).
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    /// Check if the certificate has expired relative to an explicit `now`.
    /// Used by the self-derivation verifier, which takes `now` as a parameter
    /// so it can be exercised deterministically and shared across verifiers.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        let exp = DateTime::from_timestamp(self.claims.exp, 0)
            .unwrap_or(DateTime::UNIX_EPOCH);
        now > exp
    }

    /// Get the certificate claims
    pub fn claims(&self) -> &CertificateClaims {
        &self.claims
    }

    /// Get the certified public key
    pub fn public_key(&self) -> &PublicKey {
        &self.claims.public_key
    }

    /// Get the email address
    pub fn email(&self) -> Option<&str> {
        self.claims.principal.as_email()
    }

    /// Get the issuer domain
    pub fn issuer(&self) -> &str {
        &self.claims.iss
    }

    /// Get the encoded JWT
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    // Internal: encode claims and sign with Ed25519
    fn encode_and_sign(claims: &CertificateClaims, key: &KeyPair) -> Result<String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Header for Ed25519
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        // Claims
        let claims_json = serde_json::to_string(claims)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        // Sign header.claims
        let message = format!("{}.{}", header_b64, claims_b64);
        let signature = key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", message, sig_b64))
    }

    // Internal: decode claims without verifying signature
    fn decode_claims(encoded: &str) -> Result<CertificateClaims> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCertificate("expected 3 JWT parts".into()));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: CertificateClaims = serde_json::from_slice(&claims_bytes)?;

        Ok(claims)
    }

    // Internal: verify signature
    fn verify_signature(encoded: &str, public_key: &PublicKey) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCertificate("expected 3 JWT parts".into()));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        public_key.verify(message.as_bytes(), &signature)
    }
}

/// Split an email into `(local-part, domain)`. Rejects empty parts and any
/// address that is not exactly one `@`-separated pair.
pub fn split_email(email: &str) -> Option<(&str, &str)> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    Some((local, domain))
}

/// Parse a `<base-local>+<label>@<domain>` subaddress (RFC 5233), returning
/// `(base_local, label, domain)`. The label is everything after the **first**
/// `+` in the local part and must be non-empty. Returns `None` if there is no
/// `+` in the local part (i.e. it is a bare address, not a subaddress).
pub fn parse_subaddress(email: &str) -> Option<(String, String, String)> {
    let (local, domain) = split_email(email)?;
    let (base_local, label) = local.split_once('+')?;
    if base_local.is_empty() || label.is_empty() {
        return None;
    }
    Some((base_local.to_string(), label.to_string(), domain.to_string()))
}

/// The self-derivation **name constraint** (design §2.1). A derived principal is
/// permitted iff it shares the base's domain and its local part is either
/// exactly the base local part (agent-as-self / case 1) or
/// `base-local + "+" + <non-empty label>` (subaddress / phase-2 cases).
pub fn derived_name_matches(base_email: &str, derived_email: &str) -> bool {
    let (base_local, base_domain) = match split_email(base_email) {
        Some(x) => x,
        None => return false,
    };
    let (derived_local, derived_domain) = match split_email(derived_email) {
        Some(x) => x,
        None => return false,
    };
    if base_domain != derived_domain {
        return false;
    }
    if derived_local == base_local {
        return true;
    }
    // Subaddress form: exactly `base_local` then `+` then a non-empty label.
    match derived_local.strip_prefix(base_local).and_then(|r| r.strip_prefix('+')) {
        Some(label) => !label.is_empty(),
        None => false,
    }
}

/// The **shared** self-derivation chain verifier (design §2.3, decision F) — the
/// single source of truth that both [`crate::BackedAssertion::verify`] and
/// sbo-core call, so the constrained trust path can never drift between them.
///
/// Given a fresh domain-signed `base` cert, an identity-signed `derived` agent
/// cert, the DNSSEC `domain_key`, and the current time `now`, this runs the
/// ordered checklist and returns `Ok(())` iff **all** pass:
///
/// - (a) `base` is domain-signed and **fresh**: `base.iss` equals the base
///   principal's domain, `base` verifies under `domain_key`, and `base` is not
///   expired at `now` (a **hard** expiry check — the freshness / chain-revocation
///   lever, OQ-3);
/// - (b) `derived` is signed by the **base key** (`derived.verify(base pubkey)`);
/// - (c) name constraint: `derived` principal is the base local part or a
///   `base+label` subaddress in the **same** domain; `derived.iss` equals the
///   base identity's email; `derived.typ` is [`TYP_SELF_AGENT_CERT`];
/// - (d) `derived.agent.parent` equals the base identity's email;
/// - (e) `derived.authority` is [`Authority::Closed`].
///
/// It deliberately does **not** check the warrant, audience, or assertion — the
/// caller composes those (see [`crate::BackedAssertion::verify`]).
pub fn verify_self_derived_chain(
    base: &Certificate,
    derived: &Certificate,
    domain_key: &PublicKey,
    now: DateTime<Utc>,
) -> Result<()> {
    let base_email = base
        .email()
        .ok_or_else(|| Error::InvalidCertificate("base cert has no email principal".into()))?;
    let base_domain = base
        .claims()
        .principal
        .domain()
        .ok_or_else(|| Error::InvalidCertificate("base cert email has no domain".into()))?;

    // (a) base is domain-signed and fresh.
    if base.is_any_agent() {
        return Err(Error::InvalidCertificate(
            "self-derivation base must be a plain identity certificate".into(),
        ));
    }
    if base.issuer() != base_domain {
        return Err(Error::IssuerMismatch {
            cert_issuer: base.issuer().to_string(),
            email_domain: base_domain.to_string(),
        });
    }
    base.verify(domain_key)?;
    if base.is_expired_at(now) {
        // Hard expiry (OQ-3): a stale base cert invalidates every derived cert
        // beneath it — this is phase-1's chain-revocation mechanism.
        return Err(Error::CertificateExpired);
    }

    // (b) derived is signed by the base identity key.
    derived.verify(base.public_key())?;

    // (c) name constraint, self-issuance, and the self-derived typ.
    if !derived.is_self_agent() {
        return Err(Error::InvalidCertificate(
            "derived certificate is not a self-derived agent certificate".into(),
        ));
    }
    let derived_email = derived
        .email()
        .ok_or_else(|| Error::InvalidCertificate("derived cert has no email principal".into()))?;
    if !derived_name_matches(base_email, derived_email) {
        return Err(Error::InvalidCertificate(format!(
            "self-derived principal '{derived_email}' violates the name constraint against base '{base_email}'"
        )));
    }
    if derived.issuer() != base_email {
        return Err(Error::InvalidCertificate(format!(
            "self-derived iss '{}' is not the base identity '{base_email}' (decision D)",
            derived.issuer()
        )));
    }

    // (d) the agent acts for the base identity.
    match derived.agent_parent() {
        Some(parent) if parent == base_email => {}
        Some(parent) => {
            return Err(Error::InvalidCertificate(format!(
                "self-derived agent parent '{parent}' is not the base identity '{base_email}'"
            )));
        }
        None => {
            return Err(Error::InvalidCertificate(
                "self-derived agent certificate has no agent block".into(),
            ));
        }
    }

    // (e) authority must be explicitly closed.
    if derived.authority() != Some(Authority::Closed) {
        return Err(Error::InvalidCertificate(
            "self-derived agent certificate must declare authority=closed".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_create_and_verify() {
        // Domain keypair
        let domain_key = KeyPair::generate();

        // User keypair
        let user_key = KeyPair::generate();

        // Create certificate
        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Verify with domain's public key
        cert.verify(&domain_key.public_key()).unwrap();

        // Check claims
        assert_eq!(cert.issuer(), "example.com");
        assert_eq!(cert.email(), Some("alice@example.com"));
        assert_eq!(cert.public_key(), &user_key.public_key());
        assert!(!cert.is_expired());
    }

    #[test]
    fn test_certificate_parse_and_verify() {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Parse from encoded form
        let parsed = Certificate::parse(cert.encoded()).unwrap();
        parsed.verify(&domain_key.public_key()).unwrap();

        assert_eq!(parsed.email(), Some("alice@example.com"));
    }

    #[test]
    fn agent_certificate_create_parse_and_accessors() {
        let domain_key = KeyPair::generate();
        let agent_key = KeyPair::generate();

        let cert = Certificate::create_agent(
            "example.com",
            "researcher@example.com",
            "alice@example.com",
            &agent_key.public_key(),
            Duration::hours(24),
            &domain_key,
            Some("https://registrar.example".to_string()),
        )
        .unwrap();

        assert!(cert.is_agent());
        assert_eq!(cert.agent_parent(), Some("alice@example.com"));
        assert_eq!(cert.registrar(), Some("https://registrar.example"));
        assert_eq!(cert.email(), Some("researcher@example.com"));

        let parsed = Certificate::parse(cert.encoded()).unwrap();
        parsed.verify(&domain_key.public_key()).unwrap();
        assert!(parsed.is_agent());
        assert_eq!(parsed.agent_parent(), Some("alice@example.com"));

        // A plain cert is not an agent.
        let user_key = KeyPair::generate();
        let plain = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();
        assert!(!plain.is_agent());
        assert_eq!(plain.agent_parent(), None);
    }

    #[test]
    fn malformed_typ_combinations_rejected() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();
        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        let requal = |mutate: &dyn Fn(&mut serde_json::Value)| {
            let mut claims: serde_json::Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(cert.encoded().split('.').nth(1).unwrap())
                    .unwrap(),
            )
            .unwrap();
            mutate(&mut claims);
            format!(
                "{}.{}.{}",
                cert.encoded().split('.').next().unwrap(),
                URL_SAFE_NO_PAD.encode(claims.to_string()),
                cert.encoded().split('.').nth(2).unwrap()
            )
        };

        // Unrecognized typ → rejected (fail-closed for future modules).
        let e = Certificate::parse(&requal(&|c| c["typ"] = "browserid-host-cert-v1".into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("unrecognized certificate typ"), "{e}");

        // Agent typ without the agent block → rejected.
        let e = Certificate::parse(&requal(&|c| c["typ"] = TYP_AGENT_CERT.into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("missing its agent block"), "{e}");

        // Agent block without the typ → rejected.
        let e = Certificate::parse(&requal(&|c| {
            c["agent"] = serde_json::json!({"parent": "alice@example.com"})
        }))
        .unwrap_err()
        .to_string();
        assert!(e.contains("without the agent typ"), "{e}");
    }

    #[test]
    fn test_certificate_wrong_key_rejected() {
        let domain_key = KeyPair::generate();
        let wrong_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Should fail with wrong key
        assert!(cert.verify(&wrong_key.public_key()).is_err());
    }
}
