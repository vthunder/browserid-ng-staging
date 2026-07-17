//! Agent warrants (spec §5.2, v0.4).
//!
//! A warrant is the user-signed, per-audience authorization that makes an
//! agent certificate usable: `U_priv` — the delegator's identity key, the
//! same key that signs `P_cert`s — signs a small claim binding **one agent
//! identity** to **one RP audience**, optionally with opaque scopes. The
//! delegator's `U_cert` is embedded (`parent-cert`) so the presentation is
//! self-contained; **signing-time semantics** apply, exactly as for
//! `P_cert`: the warrant must have been signed while the embedded `U_cert`
//! was valid, and stays valid until its own `exp` even after the `U_cert`
//! expires.
//!
//! Privacy is structural: one warrant names one audience, so no artifact
//! anywhere carries the delegator's full audience list, and warrants never
//! transit the IdP or registrar — an RP sees only warrants addressed to it.
//!
//! Presentation puts the warrant *inside* the backed-assertion chain
//! (`agent_cert~warrant~assertion`, spec §5.3) — see
//! [`crate::BackedAssertion`] — so a verifier cannot skip it.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::provisioning::{expired, jws_decode, jws_sign, jws_verify};
use crate::status::StatusRef;
use crate::{Certificate, Error, KeyPair, Result};

/// Claim-level `typ` of a warrant
pub const TYP_AGENT_WARRANT: &str = "browserid-agent-warrant-v1";

/// Recommended warrant validity (spec: 90 days, matching `P_cert`)
pub const WARRANT_VALIDITY_DAYS: i64 = 90;

fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::InvalidWarrant(msg.to_string())
}

/// The origin (`scheme://host[:port]`) of a URL — the part before the path.
/// Used to pin a warrant's `status.uri` to the certificate's `registrar`
/// (spec §5.3). Returns `None` if there's no `scheme://host`.
fn url_origin(u: &str) -> Option<String> {
    let (scheme, rest) = u.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantClaims {
    /// MUST be [`TYP_AGENT_WARRANT`]
    pub typ: String,
    /// The delegator (== `parent-cert.principal.email` == the agent
    /// certificate's `agent.parent`)
    pub iss: String,
    /// The agent's full identity email this warrant authorizes
    pub agent: String,
    /// Exactly one RP audience: an opaque exact-match identifier (https
    /// origin for web RPs; scheme-specific URIs like `sbo://…` allowed —
    /// no wildcards), same normalization as assertion `aud`
    pub aud: String,
    /// Opaque scope strings, meaningful only to the RP. Absent means
    /// audience-authorized but scope-unqualified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The delegator's `U_cert`, embedded so verification is self-contained
    #[serde(rename = "parent-cert")]
    pub parent_cert: String,
    /// Fast-revocation hook (core §6.4): one index per grant, allocated by
    /// the registrar, so a single warrant can be revoked without touching
    /// the agent's other grants
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
    pub iat: i64,
    pub exp: i64,
}

/// A user-signed, per-audience agent authorization (spec §5.2)
#[derive(Debug, Clone)]
pub struct Warrant {
    encoded: String,
    claims: WarrantClaims,
}

impl Warrant {
    /// Sign a warrant with the delegator's identity key. The delegator is
    /// derived from `parent_cert` (which must be a plain, email-principal
    /// certificate — an agent identity cannot be a delegator). `audience`
    /// must be an exact origin; wildcards are rejected.
    pub fn create(
        parent_cert: &Certificate,
        agent_email: &str,
        audience: &str,
        scopes: Option<Vec<String>>,
        validity: Duration,
        identity_key: &KeyPair,
    ) -> Result<Self> {
        Self::create_with_status(
            parent_cert, agent_email, audience, scopes, validity, identity_key, None,
        )
    }

    /// [`Warrant::create`] with a status-list reference (core §6.4)
    pub fn create_with_status(
        parent_cert: &Certificate,
        agent_email: &str,
        audience: &str,
        scopes: Option<Vec<String>>,
        validity: Duration,
        identity_key: &KeyPair,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        if parent_cert.is_agent() {
            return Err(invalid("an agent identity cannot be a delegator"));
        }
        let delegator = parent_cert
            .email()
            .ok_or_else(|| invalid("parent cert has no email principal"))?;
        if audience.is_empty() || audience.contains('*') {
            return Err(invalid("audience must be one exact origin (no wildcards)"));
        }

        let now = Utc::now();
        let claims = WarrantClaims {
            typ: TYP_AGENT_WARRANT.to_string(),
            iss: delegator.to_string(),
            agent: agent_email.to_string(),
            aud: audience.to_string(),
            scopes,
            parent_cert: parent_cert.encoded().to_string(),
            status,
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
        };
        let encoded = jws_sign(&claims, identity_key)?;
        Ok(Self { encoded, claims })
    }

    /// Parse (no signature check); rejects a wrong or missing `typ` and a
    /// wildcard audience
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: WarrantClaims = jws_decode(encoded, "warrant")?;
        if claims.typ != TYP_AGENT_WARRANT {
            return Err(invalid(format!("typ '{}'", claims.typ)));
        }
        if claims.aud.is_empty() || claims.aud.contains('*') {
            return Err(invalid("audience must be one exact origin (no wildcards)"));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// Cheap check for chain parsing: does this segment's claim-level `typ`
    /// say "warrant"? (Full validation happens in [`Warrant::parse`].)
    pub(crate) fn segment_is_warrant(encoded: &str) -> bool {
        jws_decode::<serde_json::Value>(encoded, "segment")
            .ok()
            .and_then(|v| v.get("typ").and_then(|t| t.as_str()).map(String::from))
            .is_some_and(|t| t == TYP_AGENT_WARRANT)
    }

    /// Verify this warrant against the agent certificate it accompanies and
    /// the verifying RP's audience (spec §5.3 step 3):
    ///
    /// 1. the embedded `parent-cert` is a plain certificate from the **same
    ///    issuer domain** as the agent cert (identity-domain rule), verified
    ///    under `issuer_key`;
    /// 2. the warrant is signed by the parent cert's subject key, with
    ///    signing-time semantics (`iat` within the parent cert's window; the
    ///    parent cert need not be currently unexpired) and is itself
    ///    unexpired;
    /// 3. `iss` == parent cert's email == the agent cert's `agent.parent`;
    /// 4. `agent` == the agent cert's `principal.email`;
    /// 5. `aud` == `audience` (the same value checked against the
    ///    assertion's `aud`).
    ///
    /// Returns the granted scopes (empty when unqualified).
    pub fn verify_for(
        &self,
        agent_cert: &Certificate,
        audience: &str,
        issuer_key: &crate::PublicKey,
    ) -> Result<Vec<String>> {
        // 1. Embedded parent cert: plain, same domain, issuer-signed.
        let parent = Certificate::parse(&self.claims.parent_cert)?;
        if parent.is_agent() {
            return Err(invalid("an agent identity cannot be a delegator"));
        }
        // Issuer match. For a domain-issued agent cert, parent and agent share
        // the same domain issuer. For a **self-derived** agent cert the leaf is
        // self-issued (decision D): its `iss` is the base identity, which is the
        // delegator == this parent cert's principal.
        if agent_cert.is_self_agent() {
            let parent_email = parent
                .email()
                .ok_or_else(|| invalid("parent cert has no email principal"))?;
            if agent_cert.issuer() != parent_email {
                return Err(invalid(format!(
                    "self-derived agent issuer '{}' does not match delegator '{}'",
                    agent_cert.issuer(),
                    parent_email
                )));
            }
        } else if parent.issuer() != agent_cert.issuer() {
            return Err(invalid(format!(
                "parent cert issuer '{}' does not match agent cert issuer '{}'",
                parent.issuer(),
                agent_cert.issuer()
            )));
        }
        parent.verify(issuer_key)?;

        // 2. Warrant under U_pub, signed while the parent cert was valid,
        //    and not itself expired.
        jws_verify(&self.encoded, parent.public_key(), "warrant")?;
        let p = parent.claims();
        if let Some(p_iat) = p.iat {
            if self.claims.iat < p_iat {
                return Err(invalid("signed before the parent cert was issued"));
            }
        }
        if self.claims.iat > p.exp {
            return Err(invalid("signed after the parent cert expired"));
        }
        if expired(self.claims.exp) {
            return Err(invalid("expired"));
        }

        // 3. Delegator consistency across all three artifacts.
        let parent_email = parent
            .email()
            .ok_or_else(|| invalid("parent cert has no email principal"))?;
        if self.claims.iss != parent_email {
            return Err(invalid(format!(
                "iss '{}' does not match parent cert principal '{}'",
                self.claims.iss, parent_email
            )));
        }
        match agent_cert.agent_parent() {
            Some(cert_parent) if cert_parent == self.claims.iss => {}
            Some(cert_parent) => {
                return Err(invalid(format!(
                    "agent cert parent '{}' does not match warrant iss '{}'",
                    cert_parent, self.claims.iss
                )));
            }
            None => return Err(invalid("accompanying certificate is not an agent cert")),
        }

        // 4. Agent identity binding.
        match agent_cert.email() {
            Some(cert_email) if cert_email == self.claims.agent => {}
            _ => {
                return Err(invalid(format!(
                    "warrant is for '{}', not this certificate's identity",
                    self.claims.agent
                )));
            }
        }

        // 5. Audience pinning — the RP's own audience, exactly.
        if self.claims.aud != audience {
            return Err(Error::AudienceMismatch {
                expected: audience.to_string(),
                actual: self.claims.aud.clone(),
            });
        }

        // 6. Revocation authority. A **self-derived** agent cert (self-derivation
        //    design §6.2 / decision G) has no `registrar` to pin to: the verifier
        //    follows whatever `status` endpoint the cert names, with NO pinning.
        //    In phase 1 a named status endpoint is fail-open — phase-1 revocation
        //    is chain expiry (§6.1) — so no status ref is required here.
        //
        //    A domain-issued agent cert keeps the strict pin (agent spec §5.3):
        //    the warrant MUST carry a status ref, the agent cert MUST name a
        //    registrar, and the ref's origin MUST be that registrar — so
        //    revocation is pinned to the authority the delegator committed to,
        //    never one the warrant names freely.
        if !agent_cert.is_self_agent() {
            let status = self
                .claims
                .status
                .as_ref()
                .ok_or_else(|| invalid("agent warrant carries no status ref (spec §5.2)"))?;
            let registrar = agent_cert
                .registrar()
                .ok_or_else(|| invalid("agent cert names no registrar (spec §5.1)"))?;
            let reg_origin = url_origin(registrar)
                .ok_or_else(|| invalid("agent cert registrar is not a valid origin"))?;
            let status_origin = url_origin(&status.uri)
                .ok_or_else(|| invalid("warrant status.uri is not a valid origin"))?;
            if status_origin != reg_origin {
                return Err(invalid(format!(
                    "warrant status authority '{status_origin}' is not the certificate's registrar '{reg_origin}'"
                )));
            }
        }

        Ok(self.claims.scopes.clone().unwrap_or_default())
    }

    pub fn claims(&self) -> &WarrantClaims {
        &self.claims
    }

    /// The delegator who signed this warrant
    pub fn delegator(&self) -> &str {
        &self.claims.iss
    }

    /// The agent identity this warrant authorizes
    pub fn agent(&self) -> &str {
        &self.claims.agent
    }

    /// The one RP audience this warrant is valid at
    pub fn audience(&self) -> &str {
        &self.claims.aud
    }

    /// The opaque scopes this warrant grants, if any.
    pub fn scopes(&self) -> Option<&[String]> {
        self.claims.scopes.as_deref()
    }

    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }

    /// The status-list reference, if this warrant carries one
    pub fn status(&self) -> Option<&StatusRef> {
        self.claims.status.as_ref()
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    struct Setup {
        idp: KeyPair,
        user: KeyPair,
        parent_cert: Certificate,
        agent_cert: Certificate,
    }

    fn setup(parent_validity: Duration) -> Setup {
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let agent = KeyPair::generate();
        let parent_cert = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &user.public_key(),
            parent_validity,
            &idp,
        )
        .unwrap();
        let agent_cert = Certificate::create_agent(
            "mingo.place",
            "attestor2@mingo.place",
            "dan@mingo.place",
            &agent.public_key(),
            Duration::hours(24),
            &idp,
            Some(REGISTRAR.to_string()),
        )
        .unwrap();
        Setup { idp, user, parent_cert, agent_cert }
    }

    const AUD: &str = "https://api.example.com";
    const REGISTRAR: &str = "https://registrar.example";

    fn status_ref() -> StatusRef {
        StatusRef {
            uri: format!("{REGISTRAR}/.well-known/browserid-status"),
            idx: 7,
        }
    }

    fn warrant(s: &Setup) -> Warrant {
        Warrant::create_with_status(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            Some(vec!["post".into(), "read".into()]),
            Duration::days(WARRANT_VALIDITY_DAYS),
            &s.user,
            Some(status_ref()),
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_and_verify() {
        let s = setup(Duration::hours(24));
        let w = warrant(&s);
        let parsed = Warrant::parse(w.encoded()).unwrap();
        let scopes = parsed
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap();
        assert_eq!(scopes, vec!["post", "read"]);
        assert_eq!(parsed.delegator(), "dan@mingo.place");
        assert_eq!(parsed.agent(), "attestor2@mingo.place");
    }

    #[test]
    fn scopeless_warrant_grants_empty() {
        let s = setup(Duration::hours(24));
        let w = Warrant::create_with_status(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
            Some(status_ref()),
        )
        .unwrap();
        let scopes = w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).unwrap();
        assert!(scopes.is_empty());
    }

    #[test]
    fn warrant_without_status_rejected() {
        // Strict (spec §5.3): an agent warrant MUST carry a status ref.
        let s = setup(Duration::hours(24));
        let w = Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap();
        let err = w
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no status ref"), "{err}");
    }

    #[test]
    fn warrant_status_not_at_cert_registrar_rejected() {
        // Strict (spec §5.3): the warrant's status authority MUST be the
        // registrar the cert names — a warrant can't point revocation
        // elsewhere.
        let s = setup(Duration::hours(24));
        let w = Warrant::create_with_status(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
            Some(StatusRef {
                uri: "https://evil.example/.well-known/browserid-status".into(),
                idx: 7,
            }),
        )
        .unwrap();
        let err = w
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not the certificate's registrar"), "{err}");
    }

    #[test]
    fn agent_cert_without_registrar_rejects_warrant() {
        // Strict (spec §5.3): the cert MUST name a registrar.
        let s = setup(Duration::hours(24));
        let agent = KeyPair::generate();
        let no_reg_cert = Certificate::create_agent(
            "mingo.place",
            "attestor2@mingo.place",
            "dan@mingo.place",
            &agent.public_key(),
            Duration::hours(24),
            &s.idp,
            None,
        )
        .unwrap();
        let w = warrant(&s);
        let err = w
            .verify_for(&no_reg_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("names no registrar"), "{err}");
    }

    #[test]
    fn wrong_audience_rejected() {
        let s = setup(Duration::hours(24));
        let w = warrant(&s);
        let err = w
            .verify_for(&s.agent_cert, "https://other.example.com", &s.idp.public_key())
            .unwrap_err();
        assert!(matches!(err, Error::AudienceMismatch { .. }));
    }

    #[test]
    fn wildcard_audience_rejected_at_create_and_parse() {
        let s = setup(Duration::hours(24));
        assert!(Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            "https://*.example.com",
            None,
            Duration::days(1),
            &s.user,
        )
        .is_err());
    }

    #[test]
    fn wrong_agent_identity_rejected() {
        let s = setup(Duration::hours(24));
        let w = Warrant::create(
            &s.parent_cert,
            "other-agent@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap();
        let err = w
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not this certificate's identity"), "{err}");
    }

    #[test]
    fn warrant_signed_by_wrong_key_rejected() {
        let s = setup(Duration::hours(24));
        let rogue = KeyPair::generate();
        let w = Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &rogue, // not the key the parent cert certifies
        )
        .unwrap();
        assert!(w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).is_err());
    }

    #[test]
    fn parent_cert_from_wrong_issuer_rejected() {
        let s = setup(Duration::hours(24));
        // Parent cert signed by a different (untrusted) key: fails under the
        // real issuer key.
        let rogue_idp = KeyPair::generate();
        let forged_parent = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &s.user.public_key(),
            Duration::hours(24),
            &rogue_idp,
        )
        .unwrap();
        let w = Warrant::create(
            &forged_parent,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap();
        assert!(w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).is_err());
    }

    #[test]
    fn delegator_mismatch_with_agent_cert_rejected() {
        let s = setup(Duration::hours(24));
        // Agent cert attributes a different parent.
        let agent = KeyPair::generate();
        let other_parent_cert = Certificate::create_agent(
            "mingo.place",
            "attestor2@mingo.place",
            "mallory@mingo.place",
            &agent.public_key(),
            Duration::hours(24),
            &s.idp,
            Some(REGISTRAR.to_string()),
        )
        .unwrap();
        let w = warrant(&s);
        let err = w
            .verify_for(&other_parent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match warrant iss"), "{err}");
    }

    #[test]
    fn signing_time_semantics() {
        // Parent cert already expired when the warrant is signed → rejected.
        let s = setup(Duration::seconds(-10));
        let w = warrant(&s);
        let err = w
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("after the parent cert expired"), "{err}");

        // Signed inside the window → valid, even though the parent cert will
        // expire long before the warrant does.
        let s = setup(Duration::seconds(2));
        let w = warrant(&s);
        w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).unwrap();
    }

    #[test]
    fn agent_cannot_be_a_delegator() {
        let s = setup(Duration::hours(24));
        // Try to use the agent cert itself as the parent.
        let err = Warrant::create(
            &s.agent_cert,
            "sub-agent@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot be a delegator"), "{err}");
    }

    #[test]
    fn typ_domain_separation() {
        let s = setup(Duration::hours(24));
        // A certificate is not a warrant; a warrant is not a certificate.
        assert!(Warrant::parse(s.parent_cert.encoded()).is_err());
        assert!(Warrant::parse(s.agent_cert.encoded()).is_err());
        let w = warrant(&s);
        assert!(Certificate::parse(w.encoded()).is_err());
        assert!(Warrant::segment_is_warrant(w.encoded()));
        assert!(!Warrant::segment_is_warrant(s.agent_cert.encoded()));
    }
}
