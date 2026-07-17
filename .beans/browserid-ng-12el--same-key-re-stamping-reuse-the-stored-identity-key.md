---
# browserid-ng-12el
title: 'Same-key re-stamping: reuse the stored identity key across cert refreshes (stable base key)'
status: todo
type: feature
priority: normal
created_at: 2026-07-17T19:15:40Z
updated_at: 2026-07-17T19:15:40Z
---

Phase-2 enhancement for the self-derivation feature (epic browserid-ng-mr2n) that dissolves OQ-3's UX pain: a self-derived agent cert signed by the base key no longer dies on every ~24h base-cert refresh.

## Finding (investigation 2026-07-17)
The browser dialog generates a FRESH identity keypair on every cert refresh — but this is VESTIGIAL (classic-Persona "generate→certify→discard" carryover), NOT a deliberate forward-secrecy/compromise-window choice. No such rationale exists in code, comments, or git history; the only documented key rationale is non-extractable CUSTODY (e2fi), about storage not rotation. And "keys rotate" is only a browser-DIALOG convention — the Rust browserid-agent ALREADY keeps a stable key + re-mints (lib.rs:498-511), and nothing in the codebase keys on key fingerprint (status is per-identity-email cert.rs:96-103; replay is aud+exp bounded; cert cache is per (issuer,email)).

## Change (client-only; broker/IdP untouched)
- dialog.js `generateCertificate` (~227-253): reuse-if-present — look up the stored non-extractable key for (issuer,email) and request a cert for the STORED pubkey instead of generateKey()+overwrite. `storeEmailKeypair` already overwrites the cert in place, so it's "same key, new cert."
- Primary path: present the stored pubkey in `_generateKeyPair`/`genKeyPair` (provisioning.js) so a classic primary re-certifies the same key. Keygen is client-side, so the classic primary certifies whatever pubkey it's handed — no primary cooperation.
- Broker `issue_certificate` (cert.rs:52-103) certifies whatever pubkey it's given — NO change.

## Safety
Non-extractable custody already prevents raw-key exfiltration (the only thing rotation bounds). Residual exposure of a stable key = an attacker who can invoke the signing handle (active same-origin compromise), which rotation doesn't mitigate. Revocation per-identity, unaffected. Stable key ≈ same practical security, materially better UX.

## Scope + phasing
Recommend SCOPED/opt-in (gate to the self-derivation base path or a flag) initially, graduate to a global "stable identity keys" change later after its own review. PHASE-2 enhancement — phase 1 (mingo admin CLI) ships fine on the bounded re-issue-on-refresh model; re-stamping is what makes long-lived derived agents (subaddress cases) pleasant.

## Doc correction
Update the self-derivation spec's OQ-3 framing: "keys rotate" is a browser-dialog convention, not a system invariant (the Rust agent already re-stamps; nothing keys on fingerprint) — so re-stamping is cheaper/safer than OQ-3 implied.
