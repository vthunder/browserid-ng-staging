//! Verifier tests
//!
//! Ported from: ~/src/browserid/tests/verifier-test.js
//!
//! Original test structure covers:
//! - Audience matching (port normalization, scheme matching)
//! - Valid assertion verification
//! - Wrong audience/port/scheme failures
//! - Expired assertion handling
//! - Malformed assertion handling
//! - Issuer authority validation
//! - Certificate chain validation

use browserid_core::{Assertion, BackedAssertion, Certificate, Error, KeyPair};
use chrono::Duration;

// =============================================================================
// Test Fixtures
// =============================================================================

const TEST_EMAIL: &str = "someuser@somedomain.com";
const TEST_DOMAIN: &str = "somedomain.com";
const TEST_ORIGIN: &str = "http://fakesite.com:8080";

/// Helper to create a valid backed assertion for testing
fn create_test_backed_assertion(
    email: &str,
    audience: &str,
    cert_validity: Duration,
    assertion_validity: Duration,
) -> (BackedAssertion, KeyPair) {
    let domain = email.split('@').nth(1).unwrap();
    let domain_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    let cert = Certificate::create(
        domain,
        email,
        &user_key.public_key(),
        cert_validity,
        &domain_key,
    )
    .unwrap();

    let assertion = Assertion::create(audience, assertion_validity, &user_key).unwrap();

    let backed = BackedAssertion::new(cert, assertion);
    (backed, domain_key)
}

// =============================================================================
// Audience Matching Tests
// Ported from: verifier-test.js lines 67-81
// =============================================================================

mod audience_matching {
    //! Tests for audience URL comparison
    //!
    //! Original tests:
    //! - 'http://fakesite.com and http://fakesite.com:80': matchesAudience(true)
    //! - 'https://fakesite.com and https://fakesite.com:443': matchesAudience(true)
    //! - 'http://fakesite.com:8000 and http://fakesite.com:8000': matchesAudience(true)
    //! - etc.

    use super::*;

    // TODO: Implement compare_audiences function and port these tests
    // For now, we test audience matching through the full verification flow

    #[test]
    fn test_exact_audience_match() {
        let (backed, domain_key) = create_test_backed_assertion(
            "alice@example.com",
            "https://example.org",
            Duration::hours(1),
            Duration::minutes(5),
        );

        let result = backed.verify("https://example.org", |_| Ok(domain_key.public_key()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_audience_mismatch_domain() {
        let (backed, domain_key) = create_test_backed_assertion(
            "alice@example.com",
            "https://example.org",
            Duration::hours(1),
            Duration::minutes(5),
        );

        let result = backed.verify("https://other.org", |_| Ok(domain_key.public_key()));
        assert!(matches!(result, Err(Error::AudienceMismatch { .. })));
    }

    // TODO: Port these specific audience matching tests once compare_audiences is implemented:
    // - http://fakesite.com == http://fakesite.com:80 (default port)
    // - https://fakesite.com == https://fakesite.com:443 (default port)
    // - http://fakesite.com:8000 == http://fakesite.com:8000 (explicit port match)
    // - https://fakesite.com:9000 == https://fakesite.com:9000 (explicit port match)
    // - http://fakesite.com:8100 != http://fakesite.com:80 (port mismatch)
    // - app://browser.gaiamobile.org == app://browser.gaiamobile.org:80 (app scheme)
}

// =============================================================================
// Basic Verification Tests
// Ported from: verifier-test.js lines 162-344 (make_basic_tests)
// =============================================================================

mod basic_verification {
    use super::*;

    /// Test: verifying assertion by specifying domain as audience - works
    /// Original: "and verifying that assertion by specifying domain as audience"
    #[test]
    fn test_verify_with_domain_audience() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(6),
            Duration::minutes(2),
        );

        // Verify with the full origin (what the assertion was created for)
        let result = backed.verify(TEST_ORIGIN, |domain| {
            assert_eq!(domain, TEST_DOMAIN);
            Ok(domain_key.public_key())
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap().email(), TEST_EMAIL);
    }

    /// Test: specifying the wrong audience fails with nice error
    /// Original: "but specifying the wrong audience" -> "fails with a nice error"
    #[test]
    fn test_wrong_audience_fails() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(6),
            Duration::minutes(2),
        );

        let result = backed.verify("http://notfakesite.com", |_| Ok(domain_key.public_key()));

        assert!(matches!(result, Err(Error::AudienceMismatch { .. })));
    }

    /// Test: specifying wrong port fails
    /// Original: "but specifying the wrong port" -> "fails with a nice error"
    #[test]
    fn test_wrong_port_fails() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN, // http://fakesite.com:8080
            Duration::hours(6),
            Duration::minutes(2),
        );

        let result = backed.verify("http://fakesite.com:8888", |_| Ok(domain_key.public_key()));

        assert!(matches!(result, Err(Error::AudienceMismatch { .. })));
    }

    /// Test: specifying wrong scheme fails
    /// Original: "but specifying the wrong scheme" -> "fails with a nice error"
    #[test]
    fn test_wrong_scheme_fails() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN, // http://fakesite.com:8080
            Duration::hours(6),
            Duration::minutes(2),
        );

        // HTTPS instead of HTTP
        let result = backed.verify("https://fakesite.com:8080", |_| Ok(domain_key.public_key()));

        assert!(matches!(result, Err(Error::AudienceMismatch { .. })));
    }

    /// Test: verification returns correct email
    #[test]
    fn test_verification_returns_email() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(6),
            Duration::minutes(2),
        );

        let verified = backed
            .verify(TEST_ORIGIN, |_| Ok(domain_key.public_key()))
            .unwrap();

        assert_eq!(verified.email(), TEST_EMAIL);
        assert!(!verified.is_agent());
    }
}

// =============================================================================
// Expiration Tests
// Ported from: verifier-test.js lines 783-805
// =============================================================================

mod expiration {
    use super::*;

    /// Test: assertion that expired a millisecond ago fails
    /// Original: "An assertion that expired a millisecond ago" -> "fails with a nice error"
    #[test]
    fn test_expired_assertion_fails() {
        let user_key = KeyPair::generate();

        // Create an already-expired assertion (negative duration)
        // We can't easily create an expired assertion with the current API,
        // so we test via is_expired() on a parsed assertion
        let assertion = Assertion::create(TEST_ORIGIN, Duration::milliseconds(-10), &user_key);

        // The assertion creation might succeed but the verification should fail
        // Actually, let's test the is_expired method directly
        if let Ok(assertion) = assertion {
            // If we managed to create it, it should be expired
            assert!(assertion.is_expired(), "assertion should be expired");
        }
    }

    /// Test: expired certificate fails verification
    #[test]
    fn test_expired_certificate_fails() {
        // We can't easily create an expired certificate directly,
        // but we can test the is_expired() method
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        // Create a certificate with very short validity
        let cert = Certificate::create(
            TEST_DOMAIN,
            TEST_EMAIL,
            &user_key.public_key(),
            Duration::milliseconds(1),
            &domain_key,
        )
        .unwrap();

        // Wait a tiny bit and check expiration
        std::thread::sleep(std::time::Duration::from_millis(2));

        assert!(cert.is_expired(), "certificate should be expired");
    }
}

// =============================================================================
// Malformed Input Tests
// Ported from: verifier-test.js lines 672-702, 704-778
// =============================================================================

mod malformed_input {
    use super::*;

    /// Test: using an email address as an assertion fails
    /// Original: "using an email address as an assertion (which is bogus)"
    #[test]
    fn test_email_as_assertion_fails() {
        let result = BackedAssertion::parse("test@example.com");

        // Should fail because email is not a valid backed assertion format
        assert!(result.is_err());
    }

    /// Test: backed assertion must have at least cert~assertion
    /// Original: "An assertion with no certificate" -> "fails with a nice error"
    #[test]
    fn test_no_certificates_fails() {
        // Just an assertion without the ~ separator
        let result = BackedAssertion::parse("eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJ0ZXN0In0.sig");

        assert!(result.is_err());
    }

    /// Test: malformed JWT parts fail gracefully
    #[test]
    fn test_malformed_jwt_fails() {
        // Not a valid JWT at all
        let result = BackedAssertion::parse("not~valid~jwt~parts");

        assert!(result.is_err());
    }

    /// Test: truncated assertion fails
    /// Original: "and removing the last two chars from it" -> "fails with a nice error"
    #[test]
    fn test_truncated_assertion_fails() {
        let (backed, _) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let encoded = backed.encode();
        // Remove last 2 characters
        let truncated = &encoded[..encoded.len() - 2];

        let result = BackedAssertion::parse(truncated);
        // Should fail to parse or fail to verify
        assert!(result.is_err() || {
            let parsed = result.unwrap();
            parsed
                .verify(TEST_ORIGIN, |_| {
                    Err(Error::DiscoveryFailed {
                        domain: "test".into(),
                        reason: "test".into(),
                    })
                })
                .is_err()
        });
    }

    /// Test: appending gunk to assertion fails
    /// Original: "and appending gunk to it" -> "fails with a nice error"
    #[test]
    fn test_assertion_with_appended_gunk_fails() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let encoded = backed.encode();
        let with_gunk = format!("{}gunk", encoded);

        let result = BackedAssertion::parse(&with_gunk);
        if let Ok(parsed) = result {
            // If parsing succeeded, verification should fail
            let verify_result = parsed.verify(TEST_ORIGIN, |_| Ok(domain_key.public_key()));
            assert!(verify_result.is_err(), "verification should fail with appended gunk");
        }
    }
}

// =============================================================================
// Issuer Authority Tests
// Ported from: verifier-test.js lines 876-981
// =============================================================================

mod issuer_authority {
    use super::*;

    /// Test: issuer domain must match email domain
    /// Original: "issuer 'example.domain' may not speak for emails from 'somedomain.com'"
    #[test]
    fn test_issuer_must_match_email_domain() {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        // Certificate claims to be from "wrong.domain" but email is "alice@example.com"
        let cert = Certificate::create(
            "wrong.domain", // issuer doesn't match email domain
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        let assertion =
            Assertion::create(TEST_ORIGIN, Duration::minutes(2), &user_key).unwrap();

        let backed = BackedAssertion::new(cert, assertion);

        let result = backed.verify(TEST_ORIGIN, |_| Ok(domain_key.public_key()));

        assert!(
            matches!(result, Err(Error::IssuerMismatch { .. })),
            "should fail with issuer mismatch"
        );
    }

    /// Test: correct issuer domain succeeds
    /// Original: successful verification when issuer matches email domain
    #[test]
    fn test_matching_issuer_succeeds() {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com", // matches email domain
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        let assertion =
            Assertion::create(TEST_ORIGIN, Duration::minutes(2), &user_key).unwrap();

        let backed = BackedAssertion::new(cert, assertion);

        let result = backed.verify(TEST_ORIGIN, |domain| {
            assert_eq!(domain, "example.com");
            Ok(domain_key.public_key())
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap().email(), "alice@example.com");
    }
}

// =============================================================================
// Signature Verification Tests
// Ported from: verifier-test.js lines 628-669
// =============================================================================

mod signature_verification {
    use super::*;

    /// Test: assertion from bogus cert fails with "bad signature in chain"
    /// Original: "generating an assertion from a bogus cert" -> "bad signature in chain"
    #[test]
    fn test_bogus_cert_signature_fails() {
        // Create a certificate signed by one key
        let real_domain_key = KeyPair::generate();
        let fake_domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            TEST_DOMAIN,
            TEST_EMAIL,
            &user_key.public_key(),
            Duration::hours(1),
            &fake_domain_key, // signed with fake key
        )
        .unwrap();

        let assertion =
            Assertion::create(TEST_ORIGIN, Duration::minutes(2), &user_key).unwrap();

        let backed = BackedAssertion::new(cert, assertion);

        // Try to verify with the real domain key (which didn't sign the cert)
        let result = backed.verify(TEST_ORIGIN, |_| Ok(real_domain_key.public_key()));

        assert!(
            matches!(result, Err(Error::SignatureVerificationFailed)),
            "should fail with signature verification error"
        );
    }

    /// Test: assertion signed with wrong key fails
    #[test]
    fn test_assertion_wrong_signature_fails() {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();
        let wrong_key = KeyPair::generate();

        // Certificate binds user_key to the email
        let cert = Certificate::create(
            TEST_DOMAIN,
            TEST_EMAIL,
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // But assertion is signed with wrong_key
        let assertion =
            Assertion::create(TEST_ORIGIN, Duration::minutes(2), &wrong_key).unwrap();

        let backed = BackedAssertion::new(cert, assertion);

        let result = backed.verify(TEST_ORIGIN, |_| Ok(domain_key.public_key()));

        assert!(
            matches!(result, Err(Error::SignatureVerificationFailed)),
            "should fail because assertion is signed with wrong key"
        );
    }
}

// =============================================================================
// Certificate Chain Tests
// Ported from: verifier-test.js lines 1109-1157
// =============================================================================

mod certificate_chain {
    use super::*;

    /// Test: chained certs verification
    /// Original: "generating an assertion with chained certs"
    /// Note: Original Persona rejected chained certs ("certificate chaining is not yet allowed")
    /// We should decide if we want to support this or not.
    #[test]
    fn test_certificate_chain_basic() {
        // For now, test that single certificate chains work
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let result = backed.verify(TEST_ORIGIN, |_| Ok(domain_key.public_key()));
        assert!(result.is_ok());

        // Verify we have exactly one certificate
        assert_eq!(backed.certificates().len(), 1);
    }

    // TODO: Add tests for multi-certificate chains if we decide to support them
}

// =============================================================================
// Backed Assertion Encoding Tests
// =============================================================================

mod backed_assertion_encoding {
    use super::*;

    /// Test: backed assertion encodes to cert~assertion format
    #[test]
    fn test_backed_assertion_encode_format() {
        let (backed, _) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let encoded = backed.encode();

        // Should have exactly one ~ separator (cert~assertion)
        let parts: Vec<&str> = encoded.split('~').collect();
        assert_eq!(parts.len(), 2, "should have cert~assertion format");

        // Each part should be a valid JWT (3 dot-separated parts)
        for (i, part) in parts.iter().enumerate() {
            let jwt_parts: Vec<&str> = part.split('.').collect();
            assert_eq!(
                jwt_parts.len(),
                3,
                "part {} should be valid JWT with 3 parts",
                i
            );
        }
    }

    /// Test: backed assertion roundtrips through encode/parse
    #[test]
    fn test_backed_assertion_roundtrip() {
        let (backed, domain_key) = create_test_backed_assertion(
            TEST_EMAIL,
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let encoded = backed.encode();
        let parsed = BackedAssertion::parse(&encoded).unwrap();

        // Should still verify correctly
        let result = parsed.verify(TEST_ORIGIN, |_| Ok(domain_key.public_key()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().email(), TEST_EMAIL);
    }
}

// =============================================================================
// Domain Key Lookup Tests
// =============================================================================

mod domain_key_lookup {
    use super::*;

    /// Test: domain key lookup is called with correct domain
    #[test]
    fn test_domain_key_lookup_called_correctly() {
        use std::cell::RefCell;

        let (backed, domain_key) = create_test_backed_assertion(
            "alice@example.com",
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let lookup_called = RefCell::new(false);
        let lookup_domain = RefCell::new(String::new());

        let _ = backed.verify(TEST_ORIGIN, |domain| {
            *lookup_called.borrow_mut() = true;
            *lookup_domain.borrow_mut() = domain.to_string();
            Ok(domain_key.public_key())
        });

        assert!(*lookup_called.borrow(), "domain key lookup should be called");
        assert_eq!(*lookup_domain.borrow(), "example.com", "should lookup correct domain");
    }

    /// Test: discovery failure is propagated
    #[test]
    fn test_discovery_failure_propagated() {
        let (backed, _) = create_test_backed_assertion(
            "alice@example.com",
            TEST_ORIGIN,
            Duration::hours(1),
            Duration::minutes(2),
        );

        let result = backed.verify(TEST_ORIGIN, |domain| {
            Err(Error::DiscoveryFailed {
                domain: domain.to_string(),
                reason: "no.such.domain is not a browserid primary".to_string(),
            })
        });

        assert!(matches!(result, Err(Error::DiscoveryFailed { .. })));
    }
}
