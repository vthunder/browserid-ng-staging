---
# browserid-ng-s5xa
title: 'Same-key re-stamping: stable client key across base-cert refreshes (phase-2 UX upgrade)'
status: todo
type: feature
priority: normal
created_at: 2026-07-17T19:16:39Z
updated_at: 2026-07-17T19:16:39Z
parent: browserid-ng-mr2n
---

Phase-2 enhancement to the self-derivation design (docs/plans/2026-07-17-label-self-delegation-agent-cert-design.md section 5.1, bean browserid-ng-u7t8). Resolves the OQ-3 UX pain: self-derived agent certs are BOUNDED by the base cert (~24h) because the browser dialog rotates the identity key per login/provision, so a long-lived derived agent must be re-issued on every base refresh.

## The insight: per-refresh key rotation is VESTIGIAL, not a security choice

- No forward-secrecy or any rotation rationale exists in code or history - a classic-Persona carryover. The only documented key rationale is NON-EXTRACTABLE custody (e2fi), about STORAGE not rotation.
- CORRECTION to the OQ-3 framing: keys rotate is only a browser-DIALOG convention, NOT a system invariant. The Rust browserid-agent ALREADY keeps a STABLE key and re-mints (browserid-agent/src/lib.rs:498-511). Nothing keys on key fingerprint: status is per-identity-EMAIL, replay is aud+exp bounded, cert cache is per (issuer, email).

## The fix (client-only, no broker change)

- dialog.js: reuse-if-present in generateCertificate; present the stored pubkey in the primary genKeyPair path.
- Broker certifies whatever pubkey it is given - NO broker change.
- Works for classic primaries (keygen is client-side).
- Safe given non-extractable custody (e2fi).

## Rollout

Phase-2, opt-in/scoped first, then graduate to global. Phase-1 design stays AS-IS (bounded, re-issue-on-refresh).
