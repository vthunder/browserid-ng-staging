//! Conformance Tests
//!
//! Ported from: ~/src/browserid/tests/conformance-test.js
//!
//! Tests JWT format compliance to ensure interoperability:
//! - Assertion format (3 parts, proper header/payload/signature)
//! - Certificate format (3 parts, proper header/payload/signature)
//! - Field presence and types
//! - Base64url encoding
//!
//! Note: Original Persona used RS256/DS128 algorithms. We use EdDSA (Ed25519).
//! The format tests remain valid; algorithm-specific tests are adapted.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use browserid_core::{Assertion, Certificate, KeyPair};
use chrono::Duration;
use serde_json::Value;

// =============================================================================
// Helper Functions
// Ported from conformance-test.js lines 47-141
// =============================================================================

/// Extract and parse JWT components without verification
/// Ported from: extractComponents() in conformance-test.js
fn extract_components(signed_object: &str) -> Result<JwtComponents, String> {
    let parts: Vec<&str> = signed_object.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "signed object must have three parts, this one has {}",
            parts.len()
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("failed to decode header: {}", e))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("failed to parse header JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("failed to decode payload: {}", e))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("failed to parse payload JSON: {}", e))?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("failed to decode signature: {}", e))?;

    Ok(JwtComponents {
        header,
        payload,
        signature: signature_bytes,
    })
}

#[derive(Debug)]
struct JwtComponents {
    header: Value,
    payload: Value,
    signature: Vec<u8>,
}

// =============================================================================
// Constants
// Ported from conformance-test.js lines 143-148
// =============================================================================

const AUDIENCE: &str = "http://foobar.com";
const ISSUER: &str = "issuer.com";
const EMAIL: &str = "john@example.com";

// =============================================================================
// Assertion Format Tests
// Ported from conformance-test.js lines 150-191
// =============================================================================

mod assertion_format {
    use super::*;

    /// Test: sign an assertion - works
    #[test]
    fn test_assertion_creation_succeeds() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair);
        assert!(assertion.is_ok(), "assertion creation should succeed");
    }

    /// Test: sign an assertion - has three parts
    /// Original: "has three part": function(err, signedObject) {
    ///             assert.equal(signedObject.split(".").length, 3);
    #[test]
    fn test_assertion_has_three_parts() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let parts: Vec<&str> = assertion.encoded().split('.').collect();
        assert_eq!(parts.len(), 3, "assertion should have exactly 3 JWT parts");
    }

    /// Test: assertion header format
    /// Original: "has proper header": function(components) {
    ///             assert.isObject(components.header);
    ///             assert.equal(components.header.alg, 'DS128');
    ///             assert.equal(Object.keys(components.header).length, 1);
    /// Note: We use EdDSA instead of DS128
    #[test]
    fn test_assertion_header_format() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();

        // Header should be an object
        assert!(components.header.is_object(), "header should be an object");

        // Algorithm should be EdDSA (we use Ed25519)
        assert_eq!(
            components.header.get("alg").and_then(|v| v.as_str()),
            Some("EdDSA"),
            "algorithm should be EdDSA"
        );

        // Header should have minimal fields (alg, optionally typ)
        let header_obj = components.header.as_object().unwrap();
        assert!(
            header_obj.len() <= 2,
            "header should have at most 2 fields (alg, typ)"
        );
    }

    /// Test: assertion payload format
    /// Original: "has proper payload": function(components) {
    ///             assert.isObject(components.payload);
    ///             assert.equal(components.payload.exp, in_a_minute.valueOf());
    ///             assert.equal(components.payload.aud, AUDIENCE);
    ///             assert.equal(Object.keys(components.payload).length, 2);
    #[test]
    fn test_assertion_payload_format() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();

        // Payload should be an object
        assert!(components.payload.is_object(), "payload should be an object");

        // Must have 'exp' (expiration) field
        let exp = components.payload.get("exp");
        assert!(exp.is_some(), "payload must have 'exp' field");
        assert!(
            exp.unwrap().is_number(),
            "'exp' should be a number (Unix timestamp)"
        );

        // Must have 'aud' (audience) field
        let aud = components.payload.get("aud");
        assert!(aud.is_some(), "payload must have 'aud' field");
        assert_eq!(
            aud.unwrap().as_str(),
            Some(AUDIENCE),
            "'aud' should match the audience"
        );

        // Should have only these required fields (exp, aud)
        let payload_obj = components.payload.as_object().unwrap();
        assert_eq!(
            payload_obj.len(),
            2,
            "assertion payload should have exactly 2 fields (exp, aud)"
        );
    }

    /// Test: assertion signature format
    /// Original: "has proper signature": function(components) {
    ///             assert.isString(components.signature);
    ///             assert.ok(components.signature.length <= 80);
    ///             assert.ok(components.signature.length > 75);
    /// Note: Ed25519 signatures are exactly 64 bytes
    #[test]
    fn test_assertion_signature_format() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();

        // Ed25519 signatures are exactly 64 bytes
        assert_eq!(
            components.signature.len(),
            64,
            "Ed25519 signature should be exactly 64 bytes"
        );
    }
}

// =============================================================================
// Certificate Format Tests
// Ported from conformance-test.js lines 193-241
// =============================================================================

mod certificate_format {
    use super::*;

    /// Test: sign a cert - works
    #[test]
    fn test_certificate_creation_succeeds() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        );

        assert!(cert.is_ok(), "certificate creation should succeed");
    }

    /// Test: sign a cert - has three parts
    /// Original: "has three parts": function(err, signedObject) {
    ///             assert.equal(signedObject.split(".").length, 3);
    #[test]
    fn test_certificate_has_three_parts() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let parts: Vec<&str> = cert.encoded().split('.').collect();
        assert_eq!(parts.len(), 3, "certificate should have exactly 3 JWT parts");
    }

    /// Test: certificate header format
    /// Original: "has proper header": function(components) {
    ///             assert.isObject(components.header);
    ///             assert.equal(components.header.alg, 'RS256');
    ///             assert.equal(Object.keys(components.header).length, 1);
    /// Note: We use EdDSA instead of RS256
    #[test]
    fn test_certificate_header_format() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let components = extract_components(cert.encoded()).unwrap();

        // Header should be an object
        assert!(components.header.is_object(), "header should be an object");

        // Algorithm should be EdDSA
        assert_eq!(
            components.header.get("alg").and_then(|v| v.as_str()),
            Some("EdDSA"),
            "algorithm should be EdDSA"
        );
    }

    /// Test: certificate payload format
    /// Original: "has proper payload": function(components) {
    ///             assert.isObject(components.payload);
    ///             assert.equal(components.payload.iss, ISSUER);
    ///             assert.equal(components.payload.exp, in_a_minute.valueOf());
    ///             assert.equal(components.payload.iat, now.valueOf());
    ///             assert.isObject(components.payload.principal);
    ///             assert.equal(components.payload.principal.email, EMAIL);
    ///             assert.equal(Object.keys(components.payload.principal).length, 1);
    ///             assert.equal(JSON.stringify(components.payload['public-key']), ...);
    ///             assert.equal(Object.keys(components.payload).length, 5);
    #[test]
    fn test_certificate_payload_format() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let components = extract_components(cert.encoded()).unwrap();

        // Payload should be an object
        assert!(components.payload.is_object(), "payload should be an object");
        let payload = components.payload.as_object().unwrap();

        // Must have 'iss' (issuer) field
        assert_eq!(
            payload.get("iss").and_then(|v| v.as_str()),
            Some(ISSUER),
            "payload must have correct 'iss' field"
        );

        // Must have 'exp' (expiration) field
        let exp = payload.get("exp");
        assert!(exp.is_some(), "payload must have 'exp' field");
        assert!(exp.unwrap().is_number(), "'exp' should be a number");

        // Should have 'iat' (issued at) field
        let iat = payload.get("iat");
        assert!(iat.is_some(), "payload should have 'iat' field");
        assert!(iat.unwrap().is_number(), "'iat' should be a number");

        // Must have 'public-key' field
        let public_key = payload.get("public-key");
        assert!(public_key.is_some(), "payload must have 'public-key' field");
        assert!(
            public_key.unwrap().is_object(),
            "'public-key' should be an object"
        );

        // Must have 'principal' field with email
        let principal = payload.get("principal");
        assert!(principal.is_some(), "payload must have 'principal' field");
        assert!(principal.unwrap().is_object(), "'principal' should be an object");

        let principal_obj = principal.unwrap().as_object().unwrap();
        assert_eq!(
            principal_obj.get("email").and_then(|v| v.as_str()),
            Some(EMAIL),
            "principal.email should match"
        );
    }

    /// Test: certificate signature format
    /// Original: "has proper signature": function(components) {
    ///             assert.isString(components.signature);
    ///             assert.ok(480 < components.signature.length);
    ///             assert.ok(components.signature.length <= 512);
    /// Note: Ed25519 signatures are exactly 64 bytes
    #[test]
    fn test_certificate_signature_format() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let components = extract_components(cert.encoded()).unwrap();

        // Ed25519 signatures are exactly 64 bytes
        assert_eq!(
            components.signature.len(),
            64,
            "Ed25519 signature should be exactly 64 bytes"
        );
    }

    /// Test: public-key in certificate has correct structure
    #[test]
    fn test_certificate_public_key_structure() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let components = extract_components(cert.encoded()).unwrap();
        let public_key = components
            .payload
            .get("public-key")
            .unwrap()
            .as_object()
            .unwrap();

        // Should have algorithm field
        assert_eq!(
            public_key.get("algorithm").and_then(|v| v.as_str()),
            Some("Ed25519"),
            "public-key should have algorithm field set to Ed25519"
        );

        // Should have publicKey field (base64url encoded)
        let pk_value = public_key.get("publicKey");
        assert!(pk_value.is_some(), "public-key should have publicKey field");
        assert!(
            pk_value.unwrap().is_string(),
            "publicKey should be a base64url string"
        );

        // Should be able to decode the public key
        let pk_b64 = pk_value.unwrap().as_str().unwrap();
        let pk_bytes = URL_SAFE_NO_PAD.decode(pk_b64);
        assert!(pk_bytes.is_ok(), "publicKey should be valid base64url");
        assert_eq!(
            pk_bytes.unwrap().len(),
            32,
            "Ed25519 public key should be 32 bytes"
        );
    }

    /// Test: principal structure in certificate
    #[test]
    fn test_certificate_principal_structure() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let components = extract_components(cert.encoded()).unwrap();
        let principal = components
            .payload
            .get("principal")
            .unwrap()
            .as_object()
            .unwrap();

        // Principal should have exactly one field: email
        assert_eq!(
            principal.len(),
            1,
            "principal should have exactly 1 field"
        );
        assert_eq!(
            principal.get("email").and_then(|v| v.as_str()),
            Some(EMAIL),
            "principal.email should match"
        );
    }
}

// =============================================================================
// Base64url Encoding Tests
// =============================================================================

mod base64url_encoding {
    use super::*;

    /// Test: JWT parts are valid base64url (no padding, URL-safe chars)
    #[test]
    fn test_jwt_uses_base64url_no_padding() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let encoded = cert.encoded();

        // Should not contain standard base64 padding
        assert!(
            !encoded.contains('='),
            "JWT should not contain '=' padding characters"
        );

        // Should not contain standard base64 chars that aren't URL-safe
        assert!(
            !encoded.contains('+'),
            "JWT should not contain '+' (use '-' instead)"
        );
        assert!(
            !encoded.contains('/'),
            "JWT should not contain '/' (use '_' instead)"
        );

        // Should only contain valid base64url characters plus '.'
        for c in encoded.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.',
                "JWT should only contain base64url chars and '.', found '{}'",
                c
            );
        }
    }

    /// Test: All three JWT parts can be decoded independently
    #[test]
    fn test_jwt_parts_independently_decodable() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let parts: Vec<&str> = assertion.encoded().split('.').collect();

        // Header should decode to valid JSON
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]);
        assert!(header_bytes.is_ok(), "header should be valid base64url");
        let header_json: Result<Value, _> = serde_json::from_slice(&header_bytes.unwrap());
        assert!(header_json.is_ok(), "header should be valid JSON");

        // Payload should decode to valid JSON
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]);
        assert!(payload_bytes.is_ok(), "payload should be valid base64url");
        let payload_json: Result<Value, _> = serde_json::from_slice(&payload_bytes.unwrap());
        assert!(payload_json.is_ok(), "payload should be valid JSON");

        // Signature should decode (but is not JSON)
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(sig_bytes.is_ok(), "signature should be valid base64url");
    }
}

// =============================================================================
// Timestamp Format Tests
// =============================================================================

mod timestamp_format {
    use super::*;

    /// Test: expiration time is in milliseconds (JavaScript convention)
    /// Note: Original Persona used milliseconds. We use seconds (Unix timestamp).
    /// This test documents our choice.
    #[test]
    fn test_expiration_is_unix_timestamp_seconds() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();
        let exp = components.payload.get("exp").unwrap().as_i64().unwrap();

        // Unix timestamp in seconds should be around 10 digits (until 2286)
        // Milliseconds would be 13 digits
        let now_secs = chrono::Utc::now().timestamp();

        // exp should be within reasonable range of now (in seconds)
        assert!(
            exp > now_secs - 60 && exp < now_secs + 120,
            "exp ({}) should be close to current time in seconds ({})",
            exp,
            now_secs
        );

        // Sanity check: if this were milliseconds, it would be way larger
        assert!(
            exp < 10_000_000_000,
            "exp should be in seconds, not milliseconds"
        );
    }

    /// Test: issued-at time is present and reasonable
    #[test]
    fn test_issued_at_is_reasonable() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::minutes(1),
            &domain_keypair,
        )
        .unwrap();

        let components = extract_components(cert.encoded()).unwrap();
        let iat = components.payload.get("iat").unwrap().as_i64().unwrap();

        let now_secs = chrono::Utc::now().timestamp();

        // iat should be very close to now
        assert!(
            iat >= now_secs - 5 && iat <= now_secs + 5,
            "iat ({}) should be very close to current time ({})",
            iat,
            now_secs
        );
    }
}

// =============================================================================
// Backed Assertion Format Tests
// =============================================================================

mod backed_assertion_format {
    use super::*;
    use browserid_core::BackedAssertion;

    /// Test: backed assertion uses ~ as separator
    #[test]
    fn test_backed_assertion_separator() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::hours(1),
            &domain_keypair,
        )
        .unwrap();

        let assertion = Assertion::create(AUDIENCE, Duration::minutes(2), &user_keypair).unwrap();

        let backed = BackedAssertion::new(cert, assertion);
        let encoded = backed.encode();

        // Should have exactly one ~ separator (for single cert)
        let tilde_count = encoded.chars().filter(|&c| c == '~').count();
        assert_eq!(
            tilde_count, 1,
            "backed assertion with one cert should have exactly one ~ separator"
        );
    }

    /// Test: backed assertion format is cert~assertion
    #[test]
    fn test_backed_assertion_structure() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::hours(1),
            &domain_keypair,
        )
        .unwrap();

        let assertion = Assertion::create(AUDIENCE, Duration::minutes(2), &user_keypair).unwrap();

        let backed = BackedAssertion::new(cert, assertion);
        let encoded = backed.encode();

        let parts: Vec<&str> = encoded.split('~').collect();
        assert_eq!(parts.len(), 2, "should have cert and assertion parts");

        // First part should be the certificate (3 dot-separated JWT parts)
        let cert_parts: Vec<&str> = parts[0].split('.').collect();
        assert_eq!(cert_parts.len(), 3, "certificate should be valid JWT");

        // Second part should be the assertion (3 dot-separated JWT parts)
        let assertion_parts: Vec<&str> = parts[1].split('.').collect();
        assert_eq!(assertion_parts.len(), 3, "assertion should be valid JWT");
    }

    /// Test: backed assertion parts match original cert and assertion
    #[test]
    fn test_backed_assertion_preserves_originals() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            ISSUER,
            EMAIL,
            &user_keypair.public_key(),
            Duration::hours(1),
            &domain_keypair,
        )
        .unwrap();

        let assertion = Assertion::create(AUDIENCE, Duration::minutes(2), &user_keypair).unwrap();

        let cert_encoded = cert.encoded().to_string();
        let assertion_encoded = assertion.encoded().to_string();

        let backed = BackedAssertion::new(cert, assertion);
        let backed_encoded = backed.encode();

        let expected = format!("{}~{}", cert_encoded, assertion_encoded);
        assert_eq!(
            backed_encoded, expected,
            "backed assertion should be cert~assertion"
        );
    }
}

// =============================================================================
// Test Vectors
// Ported from conformance-test.js lines 247-295
//
// Note: The original test vectors use RS256/DS128. Since we use Ed25519,
// we create our own test vectors for verification. The important thing is
// that we can generate and verify our own assertions consistently.
// =============================================================================

mod test_vectors {
    use super::*;
    use browserid_core::BackedAssertion;

    /// Test: Generated assertion can be parsed and re-verified
    /// This is our equivalent of the "verifying a test-vector assertion" tests
    #[test]
    fn test_roundtrip_verification() {
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        // Create a certificate and assertion
        let cert = Certificate::create(
            "example.com",
            "user@example.com",
            &user_keypair.public_key(),
            Duration::hours(1),
            &domain_keypair,
        )
        .unwrap();

        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_keypair)
                .unwrap();

        let backed = BackedAssertion::new(cert, assertion);
        let encoded = backed.encode();

        // Parse it back
        let parsed = BackedAssertion::parse(&encoded).unwrap();

        // Verify it
        let result = parsed.verify("https://relying-party.com", |_domain| {
            Ok(domain_keypair.public_key())
        });

        assert!(result.is_ok(), "roundtrip verification should succeed");
        assert_eq!(result.unwrap().email(), "user@example.com");
    }

    /// Test: We can serialize and deserialize domain public keys
    #[test]
    fn test_public_key_serialization_roundtrip() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();

        // Serialize to JSON
        let json = serde_json::to_string(&public_key).unwrap();

        // Deserialize back
        let parsed: browserid_core::PublicKey = serde_json::from_str(&json).unwrap();

        // Should be equal
        assert_eq!(public_key, parsed, "public key should survive serialization roundtrip");
    }

    /// Test: Certificates from one session can be verified in another
    /// (simulating storage and later verification)
    #[test]
    fn test_stored_assertion_verification() {
        // Session 1: Create and "store" the assertion
        let domain_keypair = KeyPair::generate();
        let user_keypair = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "stored@example.com",
            &user_keypair.public_key(),
            Duration::hours(24),
            &domain_keypair,
        )
        .unwrap();

        let assertion =
            Assertion::create("https://rp.example.com", Duration::minutes(5), &user_keypair)
                .unwrap();

        let backed = BackedAssertion::new(cert, assertion);
        let stored_assertion = backed.encode();
        let stored_domain_key = serde_json::to_string(&domain_keypair.public_key()).unwrap();

        // Session 2: Load and verify (simulating a different context)
        let loaded_assertion = BackedAssertion::parse(&stored_assertion).unwrap();
        let loaded_domain_key: browserid_core::PublicKey =
            serde_json::from_str(&stored_domain_key).unwrap();

        let result =
            loaded_assertion.verify("https://rp.example.com", |_| Ok(loaded_domain_key.clone()));

        assert!(result.is_ok());
        assert_eq!(result.unwrap().email(), "stored@example.com");
    }
}
