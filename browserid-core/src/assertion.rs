//! Identity assertions for BrowserID-NG
//!
//! An assertion proves a user's identity to a relying party.
//! A backed assertion includes the certificate chain for verification.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{Certificate, Error, KeyPair, PublicKey, Result, Warrant};

/// Claims in an identity assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionClaims {
    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Audience (the relying party origin this assertion is for)
    pub aud: String,
}

/// An identity assertion claiming an email for a specific audience
#[derive(Debug, Clone)]
pub struct Assertion {
    /// The encoded JWT
    encoded: String,
    /// The decoded claims
    claims: AssertionClaims,
}

impl Assertion {
    /// Create and sign a new assertion
    ///
    /// # Arguments
    /// * `audience` - The origin of the relying party (e.g., "https://example.com")
    /// * `validity` - How long the assertion should be valid (typically 2-5 minutes)
    /// * `user_key` - The user's signing key
    pub fn create(audience: &str, validity: Duration, user_key: &KeyPair) -> Result<Self> {
        let now = Utc::now();
        let exp = now + validity;

        let claims = AssertionClaims {
            exp: exp.timestamp(),
            aud: audience.to_string(),
        };

        let encoded = Self::encode_and_sign(&claims, user_key)?;

        Ok(Self { encoded, claims })
    }

    /// Parse an assertion from its encoded form (does not verify signature)
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims = Self::decode_claims(encoded)?;
        Ok(Self {
            encoded: encoded.to_string(),
            claims,
        })
    }

    /// Verify the assertion signature against a public key
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        Self::verify_signature(&self.encoded, public_key)
    }

    /// Check if the assertion has expired
    pub fn is_expired(&self) -> bool {
        let exp = chrono::DateTime::from_timestamp(self.claims.exp, 0)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH);
        Utc::now() > exp
    }

    /// Get the assertion claims
    pub fn claims(&self) -> &AssertionClaims {
        &self.claims
    }

    /// Get the audience
    pub fn audience(&self) -> &str {
        &self.claims.aud
    }

    /// Get the encoded JWT
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    // Internal: encode claims and sign
    fn encode_and_sign(claims: &AssertionClaims, key: &KeyPair) -> Result<String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        let claims_json = serde_json::to_string(claims)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let message = format!("{}.{}", header_b64, claims_b64);
        let signature = key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", message, sig_b64))
    }

    // Internal: decode claims
    fn decode_claims(encoded: &str) -> Result<AssertionClaims> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidAssertion("expected 3 JWT parts".into()));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: AssertionClaims = serde_json::from_slice(&claims_bytes)?;

        Ok(claims)
    }

    // Internal: verify signature
    fn verify_signature(encoded: &str, public_key: &PublicKey) -> Result<()> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidAssertion("expected 3 JWT parts".into()));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        public_key.verify(message.as_bytes(), &signature)
    }
}

/// Agent attribution surfaced by a verified agent presentation (spec §5.3
/// step 5, self-derivation design §3.5/E.1): who the agent **acts as**, who
/// delegated to it, and the scopes its delegator granted at this audience.
///
/// `acts_as` and `scopes` travel together and are non-optional, so a caller
/// cannot reduce an agent presentation to a bare principal string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAttribution {
    /// The verified principal this presentation acts as — the leaf agent
    /// certificate's principal (for a self-derived agent-as-self cert this is
    /// the base identity itself).
    pub acts_as: String,
    /// The delegator (`agent.parent` from the certificate, cross-checked
    /// against the warrant)
    pub parent: String,
    /// Scopes from the warrant (empty when the warrant is scope-unqualified)
    pub scopes: Vec<String>,
}

/// What a verified backed assertion yields (self-derivation design decision
/// E.1 — the strongest naive-RP mitigation). This is deliberately an **enum**,
/// not a struct with an easily-dropped `Option`: a caller must match the
/// [`VerifiedPresentation::Agent`] arm to obtain the email, so an agent
/// presentation can never be silently mistaken for a full-authority identity.
#[derive(Debug, Clone)]
pub enum VerifiedPresentation {
    /// A plain identity (or login) presentation: full authority as `email`.
    Identity {
        /// The certified email.
        email: String,
    },
    /// An agent presentation: authority is warrant-defined. Carries the
    /// non-optional [`AgentAttribution`] (`acts_as` + `parent` + `scopes`).
    Agent(AgentAttribution),
}

impl VerifiedPresentation {
    /// The verified principal email, whichever variant this is. For an agent
    /// presentation this is who it **acts as** — reading it does not discard
    /// the fact that the presentation is an agent's (use [`Self::agent`] /
    /// [`Self::is_agent`] to observe that).
    pub fn email(&self) -> &str {
        match self {
            Self::Identity { email } => email,
            Self::Agent(a) => &a.acts_as,
        }
    }

    /// The agent attribution, present iff this is an agent presentation.
    pub fn agent(&self) -> Option<&AgentAttribution> {
        match self {
            Self::Agent(a) => Some(a),
            Self::Identity { .. } => None,
        }
    }

    /// Whether this is an agent presentation.
    pub fn is_agent(&self) -> bool {
        matches!(self, Self::Agent(_))
    }
}

/// A backed identity assertion: certificate chain + assertion
///
/// Format: `<cert-1>~<cert-2>~...~<cert-n>~<assertion>`, and for agent
/// presentations (spec §5.3) `<agent-cert>~<warrant>~<assertion>` — the
/// warrant sits between the leaf certificate and the assertion, so it is
/// load-bearing in the format and cannot be skipped.
///
/// The certificate chain goes from user cert (signed by domain) to assertion.
/// In the simple case, there's just one certificate.
#[derive(Debug, Clone)]
pub struct BackedAssertion {
    /// The certificate chain (typically just one certificate)
    certificates: Vec<Certificate>,
    /// The warrant, present iff the leaf certificate is an agent certificate
    warrant: Option<Warrant>,
    /// The assertion
    assertion: Assertion,
}

impl BackedAssertion {
    /// Create a backed assertion with a single certificate
    pub fn new(certificate: Certificate, assertion: Assertion) -> Self {
        Self {
            certificates: vec![certificate],
            warrant: None,
            assertion,
        }
    }

    /// Create an agent presentation: `agent_cert~warrant~assertion`
    pub fn new_agent(agent_cert: Certificate, warrant: Warrant, assertion: Assertion) -> Self {
        Self {
            certificates: vec![agent_cert],
            warrant: Some(warrant),
            assertion,
        }
    }

    /// Create a self-derived agent presentation:
    /// `[base_cert, agent_cert]~warrant~assertion` (self-derivation design
    /// §2.2). The `agent_cert` is the self-derived leaf (typ
    /// [`crate::certificate::TYP_SELF_AGENT_CERT`]) and `base_cert` is the fresh
    /// domain-signed base it chains to.
    pub fn new_self_derived_agent(
        base_cert: Certificate,
        agent_cert: Certificate,
        warrant: Warrant,
        assertion: Assertion,
    ) -> Self {
        Self {
            certificates: vec![base_cert, agent_cert],
            warrant: Some(warrant),
            assertion,
        }
    }

    /// Create a backed assertion with a certificate chain
    pub fn with_chain(certificates: Vec<Certificate>, assertion: Assertion) -> Self {
        Self {
            certificates,
            warrant: None,
            assertion,
        }
    }

    /// Parse a backed assertion from the `cert~…~assertion` /
    /// `cert~…~warrant~assertion` format.
    ///
    /// Fail-closed structure (core §5, agent spec §5.3): every certificate
    /// segment must be of a recognized type (`Certificate::parse` rejects
    /// unknown `typ`s); a warrant may appear only immediately before the
    /// assertion; an agent certificate must be the leaf and **must** be
    /// followed by a warrant; a plain presentation must not carry one.
    pub fn parse(encoded: &str) -> Result<Self> {
        let parts: Vec<&str> = encoded.split('~').collect();
        if parts.len() < 2 {
            return Err(Error::InvalidAssertion(
                "backed assertion must have at least one certificate and one assertion".into(),
            ));
        }

        let assertion_str = parts.last().unwrap();
        let mut cert_strs = &parts[..parts.len() - 1];

        // A warrant, if present, is the last segment before the assertion.
        // (Anywhere else it fails Certificate::parse below — fail closed.)
        let warrant = match cert_strs.last() {
            Some(seg) if Warrant::segment_is_warrant(seg) => {
                cert_strs = &cert_strs[..cert_strs.len() - 1];
                Some(Warrant::parse(seg)?)
            }
            _ => None,
        };

        let certificates: Result<Vec<Certificate>> =
            cert_strs.iter().map(|s| Certificate::parse(s)).collect();
        let certificates = certificates?;

        let assertion = Assertion::parse(assertion_str)?;

        let backed = Self {
            certificates,
            warrant,
            assertion,
        };
        backed.check_structure()?;
        Ok(backed)
    }

    /// Structural agent rules — enforced at parse so a malformed presentation
    /// never even reaches verification.
    fn check_structure(&self) -> Result<()> {
        let leaf = self.certificates.last().ok_or_else(|| {
            Error::InvalidAssertion("backed assertion has no certificate".into())
        })?;
        if self
            .certificates
            .iter()
            .take(self.certificates.len() - 1)
            .any(|c| c.is_any_agent())
        {
            return Err(Error::InvalidAssertion(
                "an agent certificate must be the leaf of the chain".into(),
            ));
        }
        // A self-derived agent leaf is preceded by exactly one plain base cert
        // (self-derivation design §2.2 / §7): `[base, self_agent]`.
        if leaf.is_self_agent() {
            if self.certificates.len() != 2 {
                return Err(Error::InvalidAssertion(
                    "a self-derived agent presentation must carry exactly one base certificate"
                        .into(),
                ));
            }
            if self.certificates[0].is_any_agent() {
                return Err(Error::InvalidAssertion(
                    "the base of a self-derived presentation must be a plain identity certificate"
                        .into(),
                ));
            }
        }
        match (leaf.is_any_agent(), &self.warrant) {
            (true, None) => Err(Error::WarrantRequired),
            (false, Some(_)) => Err(Error::InvalidAssertion(
                "warrant present but the leaf certificate is not an agent certificate".into(),
            )),
            _ => Ok(()),
        }
    }

    /// Encode to the `cert~…~[warrant~]assertion` format
    pub fn encode(&self) -> String {
        let mut parts: Vec<&str> = self.certificates.iter().map(|c| c.encoded()).collect();
        if let Some(warrant) = &self.warrant {
            parts.push(warrant.encoded());
        }
        parts.push(self.assertion.encoded());
        parts.join("~")
    }

    /// Verify the entire chain, warrant (for agent presentations), and
    /// assertion (core §6.2 + agent spec §5.3).
    ///
    /// # Arguments
    /// * `expected_audience` - The audience the assertion (and any warrant)
    ///   must name
    /// * `get_domain_key` - Function to retrieve a domain's public key
    ///
    /// Returns the verified identity — email plus agent attribution when the
    /// leaf certificate is an agent certificate. In that case the warrant is
    /// verified unconditionally: signed by the delegator's certified key,
    /// bound to this agent identity and to `expected_audience`.
    pub fn verify<F>(&self, expected_audience: &str, get_domain_key: F) -> Result<VerifiedPresentation>
    where
        F: Fn(&str) -> Result<PublicKey>,
    {
        // Structural rules first (constructors can bypass parse).
        self.check_structure()?;

        // Check assertion audience
        if self.assertion.audience() != expected_audience {
            return Err(Error::AudienceMismatch {
                expected: expected_audience.to_string(),
                actual: self.assertion.audience().to_string(),
            });
        }

        // Check assertion expiration
        if self.assertion.is_expired() {
            return Err(Error::AssertionExpired);
        }

        // Verify assertion signature with the certificate's public key
        let user_cert = self.certificates.last().unwrap();
        self.assertion.verify(user_cert.public_key())?;

        // Check certificate expiration
        if user_cert.is_expired() {
            return Err(Error::CertificateExpired);
        }

        // Self-derived agent presentation (`[base, self_agent]~warrant~assertion`,
        // self-derivation design §2.3). This chain does NOT reduce to the classic
        // domain-signed path — the leaf `iss` is the base identity, not the domain
        // — so it is verified through the shared checklist and returns early.
        if user_cert.is_self_agent() {
            // check_structure guarantees exactly `[base, self_agent]`.
            let base = &self.certificates[0];
            let base_domain = base.claims().principal.domain().ok_or_else(|| {
                Error::InvalidCertificate("base cert email has no domain".into())
            })?;
            let domain_key = get_domain_key(base_domain)?;
            crate::certificate::verify_self_derived_chain(
                base,
                user_cert,
                &domain_key,
                Utc::now(),
            )?;

            // The warrant is load-bearing and mandatory (WarrantRequired), and is
            // verified with the BASE cert as its parent-cert under the domain key.
            let warrant = self.warrant.as_ref().ok_or(Error::WarrantRequired)?;
            let scopes = warrant.verify_for(user_cert, expected_audience, &domain_key)?;

            let acts_as = user_cert
                .email()
                .ok_or_else(|| Error::InvalidCertificate("certificate has no email".into()))?
                .to_string();
            let parent = user_cert
                .agent_parent()
                .expect("check_structure: self-agent leaf has an agent block")
                .to_string();
            return Ok(VerifiedPresentation::Agent(AgentAttribution {
                acts_as,
                parent,
                scopes,
            }));
        }

        // Get the email and domain from the certificate
        let email = user_cert
            .email()
            .ok_or_else(|| Error::InvalidCertificate("certificate has no email".into()))?;

        let domain = user_cert
            .claims()
            .principal
            .domain()
            .ok_or_else(|| Error::InvalidCertificate("cannot extract domain from email".into()))?;

        // Check that the issuer matches the email domain
        if user_cert.issuer() != domain {
            return Err(Error::IssuerMismatch {
                cert_issuer: user_cert.issuer().to_string(),
                email_domain: domain.to_string(),
            });
        }

        // Verify certificate chain (for now, just single certificate)
        // TODO: Support longer chains with intermediate certificates
        let issuer_key = if self.certificates.len() == 1 {
            let domain_key = get_domain_key(domain)?;
            user_cert.verify(&domain_key)?;
            domain_key
        } else {
            // For longer chains, verify each cert with the previous cert's public key
            // The root cert is verified with the domain key
            let root_domain = self.certificates[0]
                .claims()
                .principal
                .domain()
                .ok_or_else(|| {
                    Error::InvalidCertificate("cannot extract domain from root cert".into())
                })?;
            let domain_key = get_domain_key(root_domain)?;
            self.certificates[0].verify(&domain_key)?;

            for i in 1..self.certificates.len() {
                let prev_cert = &self.certificates[i - 1];
                self.certificates[i].verify(prev_cert.public_key())?;

                if self.certificates[i].is_expired() {
                    return Err(Error::CertificateExpired);
                }
            }
            domain_key
        };

        // Agent presentation: the warrant is load-bearing (spec §5.3). The
        // delegator's embedded parent cert chains to the same issuer key —
        // delegator and agent share one IdP (identity-domain rule).
        match &self.warrant {
            Some(warrant) => {
                let scopes = warrant.verify_for(user_cert, expected_audience, &issuer_key)?;
                let parent = user_cert
                    .agent_parent()
                    .expect("check_structure: warrant implies agent cert")
                    .to_string();
                Ok(VerifiedPresentation::Agent(AgentAttribution {
                    acts_as: email.to_string(),
                    parent,
                    scopes,
                }))
            }
            None => Ok(VerifiedPresentation::Identity {
                email: email.to_string(),
            }),
        }
    }

    /// Get the certificates in the chain
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// The warrant, present iff this is an agent presentation
    pub fn warrant(&self) -> Option<&Warrant> {
        self.warrant.as_ref()
    }

    /// Get the assertion
    pub fn assertion(&self) -> &Assertion {
        &self.assertion
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assertion_create_and_verify() {
        let user_key = KeyPair::generate();

        let assertion =
            Assertion::create("https://example.com", Duration::minutes(5), &user_key).unwrap();

        assertion.verify(&user_key.public_key()).unwrap();
        assert_eq!(assertion.audience(), "https://example.com");
        assert!(!assertion.is_expired());
    }

    #[test]
    fn test_backed_assertion_verify() {
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

        // Create assertion
        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key)
                .unwrap();

        // Bundle into backed assertion
        let backed = BackedAssertion::new(cert, assertion);

        // Verify
        let verified = backed
            .verify("https://relying-party.com", |domain| {
                assert_eq!(domain, "example.com");
                Ok(domain_key.public_key())
            })
            .unwrap();

        assert_eq!(verified.email(), "alice@example.com");
        assert!(!verified.is_agent());
    }

    #[test]
    fn test_backed_assertion_encode_parse() {
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

        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key)
                .unwrap();

        let backed = BackedAssertion::new(cert, assertion);
        let encoded = backed.encode();

        // Should contain a ~ separator
        assert!(encoded.contains('~'));

        // Parse it back
        let parsed = BackedAssertion::parse(&encoded).unwrap();

        // Verify
        let verified = parsed
            .verify("https://relying-party.com", |_| Ok(domain_key.public_key()))
            .unwrap();

        assert_eq!(verified.email(), "alice@example.com");
    }

    // ---- agent presentations (spec §5.3) ----

    struct AgentSetup {
        domain_key: KeyPair,
        agent_key: KeyPair,
        user_key: KeyPair,
        parent_cert: Certificate,
        agent_cert: Certificate,
    }

    const RP: &str = "https://relying-party.com";
    const REGISTRAR: &str = "https://registrar.example";

    fn agent_setup() -> AgentSetup {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();
        let agent_key = KeyPair::generate();
        let parent_cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(24),
            &domain_key,
        )
        .unwrap();
        let agent_cert = Certificate::create_agent(
            "example.com",
            "researcher@example.com",
            "alice@example.com",
            &agent_key.public_key(),
            Duration::hours(24),
            &domain_key,
            Some(REGISTRAR.to_string()),
        )
        .unwrap();
        AgentSetup { domain_key, agent_key, user_key, parent_cert, agent_cert }
    }

    fn agent_warrant(s: &AgentSetup, audience: &str) -> Warrant {
        Warrant::create_with_status(
            &s.parent_cert,
            "researcher@example.com",
            audience,
            Some(vec!["post".into()]),
            Duration::days(30),
            &s.user_key,
            Some(crate::status::StatusRef {
                uri: format!("{REGISTRAR}/.well-known/browserid-status"),
                idx: 1,
            }),
        )
        .unwrap()
    }

    #[test]
    fn agent_presentation_roundtrip_and_verify() {
        let s = agent_setup();
        let assertion = Assertion::create(RP, Duration::minutes(5), &s.agent_key).unwrap();
        let backed = BackedAssertion::new_agent(
            s.agent_cert.clone(),
            agent_warrant(&s, RP),
            assertion,
        );
        let encoded = backed.encode();
        assert_eq!(encoded.matches('~').count(), 2, "agent_cert~warrant~assertion");

        let parsed = BackedAssertion::parse(&encoded).unwrap();
        let verified = parsed
            .verify(RP, |_| Ok(s.domain_key.public_key()))
            .unwrap();
        assert_eq!(verified.email(), "researcher@example.com");
        let agent = verified.agent().expect("agent attribution");
        assert_eq!(agent.acts_as, "researcher@example.com");
        assert_eq!(agent.parent, "alice@example.com");
        assert_eq!(agent.scopes, vec!["post"]);
    }

    #[test]
    fn agent_cert_without_warrant_rejected() {
        let s = agent_setup();
        let assertion = Assertion::create(RP, Duration::minutes(5), &s.agent_key).unwrap();
        // Hand-build the bare (warrant-less) wire form an attacker with a
        // leaked cert+key would present.
        let bare = format!("{}~{}", s.agent_cert.encoded(), assertion.encoded());
        assert!(matches!(
            BackedAssertion::parse(&bare),
            Err(Error::WarrantRequired)
        ));
        // The constructor path is equally fail-closed at verify.
        let backed = BackedAssertion::new(s.agent_cert.clone(), assertion);
        assert!(matches!(
            backed.verify(RP, |_| Ok(s.domain_key.public_key())),
            Err(Error::WarrantRequired)
        ));
    }

    #[test]
    fn warrant_on_plain_cert_rejected() {
        let s = agent_setup();
        let user2 = KeyPair::generate();
        let plain = Certificate::create(
            "example.com",
            "bob@example.com",
            &user2.public_key(),
            Duration::hours(24),
            &s.domain_key,
        )
        .unwrap();
        let assertion = Assertion::create(RP, Duration::minutes(5), &user2).unwrap();
        let wired = format!(
            "{}~{}~{}",
            plain.encoded(),
            agent_warrant(&s, RP).encoded(),
            assertion.encoded()
        );
        let err = BackedAssertion::parse(&wired).unwrap_err().to_string();
        assert!(err.contains("not an agent certificate"), "{err}");
    }

    #[test]
    fn warrant_for_other_audience_rejected() {
        let s = agent_setup();
        let assertion = Assertion::create(RP, Duration::minutes(5), &s.agent_key).unwrap();
        let backed = BackedAssertion::new_agent(
            s.agent_cert.clone(),
            agent_warrant(&s, "https://other-party.com"),
            assertion,
        );
        assert!(matches!(
            backed.verify(RP, |_| Ok(s.domain_key.public_key())),
            Err(Error::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn unrecognized_cert_typ_rejected_in_chain() {
        // A chain whose "certificate" carries an unknown typ must fail to
        // parse (core §4.1/§6.2 fail-closed rule).
        let s = agent_setup();
        let assertion = Assertion::create(RP, Duration::minutes(5), &s.agent_key).unwrap();
        // Splice a future-typed cert by re-encoding claims by hand.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut claims: serde_json::Value =
            serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(s.agent_cert.encoded().split('.').nth(1).unwrap())
                    .unwrap(),
            )
            .unwrap();
        claims["typ"] = "browserid-agent-cert-v99".into();
        let forged = format!(
            "{}.{}.{}",
            s.agent_cert.encoded().split('.').next().unwrap(),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            s.agent_cert.encoded().split('.').nth(2).unwrap()
        );
        let wired = format!(
            "{}~{}~{}",
            forged,
            agent_warrant(&s, RP).encoded(),
            assertion.encoded()
        );
        let err = BackedAssertion::parse(&wired).unwrap_err().to_string();
        assert!(err.contains("unrecognized certificate typ"), "{err}");
    }

    #[test]
    fn test_audience_mismatch_rejected() {
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

        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key)
                .unwrap();

        let backed = BackedAssertion::new(cert, assertion);

        // Verify with wrong audience should fail
        let result = backed.verify("https://wrong-audience.com", |_| Ok(domain_key.public_key()));
        assert!(matches!(result, Err(Error::AudienceMismatch { .. })));
    }
}
