//! BrowserID-NG Core Library
//!
//! Implements the BrowserID protocol for email-based identity:
//! - Domains publish keys and sign certificates for their users
//! - Users create assertions proving identity to relying parties
//! - Verifiers check certificate chains back to domain keys

pub mod keys;
pub mod certificate;
pub mod assertion;
pub mod discovery;
pub mod dns;
pub mod error;
pub mod provisioning;
pub mod rp_auth;
pub mod status;
pub mod warrant;

pub use keys::{KeyPair, PublicKey};
pub use certificate::{
    derived_name_matches, parse_subaddress, split_email, verify_self_derived_chain, AgentClaims,
    Authority, Certificate, TYP_AGENT_CERT, TYP_SELF_AGENT_CERT,
};
pub use assertion::{AgentAttribution, Assertion, BackedAssertion, VerifiedPresentation};
pub use dns::{DnsRecord, DnssecStatus, DnsLookupResult};
pub use error::Error;
pub use provisioning::{
    Action, Constraint, Endorsement, ExternalWarrantRequest, ProvisioningCert,
    ProvisioningRequest, RequestBundle, VerifiedExternalRequest, VerifiedRequest, WarrantGrant,
    MAX_WARRANT_GRANTS,
};
pub use rp_auth::{RpChallenge, TokenRequest, TokenResponse};
pub use status::{StatusList, StatusListToken, StatusRef, TYP_STATUS_LIST};
pub use warrant::{Warrant, TYP_AGENT_WARRANT, WARRANT_VALIDITY_DAYS};

/// Result type for browserid-core operations
pub type Result<T> = std::result::Result<T, Error>;
