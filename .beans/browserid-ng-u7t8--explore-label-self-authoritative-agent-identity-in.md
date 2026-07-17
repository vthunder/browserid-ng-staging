---
# browserid-ng-u7t8
title: 'Explore: +label self-authoritative agent identity (inbox@domain authoritative for inbox+label@domain)'
status: todo
type: task
priority: high
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T19:17:02Z
parent: browserid-ng-mr2n
---

Roadmap item 4 (see the CLI-auth epic). The elegant path to an agent identity for an external primary that doesn't self-host agent provisioning.

## Idea
Make it an official spec rule that `inbox@domain` is authoritative for any `inbox+label@domain` subaddress (RFC5233-style plus-addressing, already an inbox=inbox+label convention). Then `danmills@sandmill.org`'s existing classic cert + key can self-authorize a `danmills+mingo-cli@sandmill.org` AGENT identity: the base identity directly warrants the agent key as the +label subaddress, no sandmill.org IdP mint and no browserid.me hosting.

## What to determine
- Crypto/chain: does the standard agent presentation require an IdP-signed agent_cert (assertion.rs enforces agent cert leaf), or can the base identity self-issue a +label agent cert (base key signs it), spec'd as valid? Trace assertion.rs / certificate.rs / warrant verification.
- browserid verification: would a `danmills+mingo-cli@sandmill.org` agent cert, self-signed by the danmills@sandmill.org key, be accepted under a +label-authoritative rule? What changes in verify?
- sbo attribution: does the daemon's attributed_email / resolve_creator need to canonicalize `x+label@d` -> `x@d` for `roles.admin` matching (so a +label agent write matches admin = danmills@sandmill.org)? OR do we match the +label form directly? Trace validate.rs resolve_creator + evaluate.rs canonical_name_ref.
- Security: the +label-authoritative rule means anyone holding the base cert controls all +label variants (intended). Any downside (e.g. an RP that treats x+label@d as a distinct principal)? Note it.

Deliverable: is (4) feasible, what exact spec + code changes it needs (browserid cert verify + sbo attribution), and whether it beats (3). Read-only exploration first.

## VERDICT (2026-07-17): feasible but NOT a free cheat — needs trust-root changes in TWO verifiers

The '+' rule cannot cheat past the core requirement that the agent LEAF cert be signed by the IdP's DNSSEC domain key. That requirement is enforced INDEPENDENTLY in:
- browserid-core assertion.rs (verify: leaf issuer must == domain, verified against get_domain_key; check_structure: agent leaf + warrant mandatory) and warrant.rs (parent-cert verified under the domain key; warrant binds the agent by EMAIL, never a raw key — so no "warrant delegates to a raw agent key" path exists).
- sbo-core/attribution.rs (verify_attribution_with_warrant independently re-verifies the agent cert against the _browserid.<iss> DNSSEC key via extract_provider_key).

So a `danmills+mingo-cli@sandmill.org` cert self-signed by the danmills@sandmill.org USER key fails in BOTH cores. Making it work requires a NEW self-issued 2-link chain (domain→identity→+label-agent, verified against the identity key not the domain key) + a +label principal-relationship rule, added to browserid-core (certificate.rs + assertion.rs + warrant.rs) AND sbo-core/attribution.rs — security-critical, in two codebases. It also LOSES the per-agent revocation anchor (self-signed certs have no registrar/status, which warrant.rs verify_for currently requires) — you'd have to invent a self-hosted status scheme.

Role-matching (the part I worried about) is ALREADY solved: the daemon's `as:` path (authorize.rs warrant_effective_email) resolves the effective author to the base email (danmills@sandmill.org) when the warrant carries as:<delegator> + a path: scope — so a +label agent acting as: danmills@sandmill.org already matches roles.admin with ZERO canonicalization changes. BUT this still needs the agent cert to exist+verify (the mint) — exactly what item 4 tries to remove.

CONCLUSION: item 4 is NOT cleaner than item 3. It trades item 3's "browser.me UI + hosting" for "loosen the cert-chain trust root in two independent security-critical verifiers + invent self-hosted revocation." Recommend item 3.


## DESIGN SPEC (2026-07-17) — chosen direction per dan, over item 3

Full spec + change inventory committed at docs/plans/2026-07-17-label-self-delegation-agent-cert-design.md.

Design: name-constrained self-delegation. Chain becomes domain key -> BASE danmills@sandmill.org cert (domain-signed, short-lived) -> danmills+mingo-cli@sandmill.org AGENT cert signed by danmills' OWN identity key. NEW constrained trust path (an addition, not a weakening of the domain-signed path): an agent cert MAY be signed by an identity cert's key iff agent local-part == <base>+<label> AND <base>@<domain> == signing base cert principal AND same domain/issuer. Base cert embedded fresh at presentation (self-contained, offline-verifiable). New typ TYP_SELF_AGENT_CERT distinguishes it (fail-closed for old verifiers).

Revocation: (1) CHAIN = short-lived base cert; not renewing it kills all +label agents (expiry-driven, no CRL at the dumb primary). (2) PER-AGENT = self-issued cert bakes in a status ref pointing at browserid.me; browserid.me publishes a signed status list + /account revoke control, owner authenticated by a normal browserid assertion as RP.

Change inventory (EXISTS vs NEW, security-critical in TWO cores — must mirror):
- browserid-core certificate.rs (new typ+constructor, Medium), assertion.rs verify/check_structure (Medium/Large, high risk), warrant.rs verify_for step-6 revocation pin generalization (Small).
- sbo-core attribution.rs verify_attribution_with_warrant/_with_provider_key (Medium/Large, must mirror core exactly). Daemon as:/role-matching needs NO change (already collapses +label -> base).
- broker/registrar: new browserid.me status-authority service + account.html revoke UI (Medium; CSP hash gotcha).
- browserid-agent lib.rs + mingo login.rs: self-issue path replacing the failed /provision/mint; `mingo login --idp` becomes unnecessary.

Open questions: status-subject pre-registration at browserid.me; status-URI trust/pinning (allowlist); base-cert refresh cadence; typ-vs-claim marker; keeping the two verifiers in sync; web RPs treating x+label@d as a distinct principal.


## SPEC v2 (2026-07-17) — GENERALIZED to a self-derivation primitive

Revised design at docs/plans/2026-07-17-label-self-delegation-agent-cert-design.md (v2). What changed from v1:

- GENERALIZED (A): one self-derivation rule. Base user@domain (holding its domain-signed base cert+key) self-signs a derived cert, principal in {self, +label}, type in {agent, regular}. Four cases, one verification path: agent-as-self, agent-as-subaddress, regular-subaddress LOGIN (per-site privacy), and the domain-signed base root.
- RETIRED as: (B): acting identity = the derived cert's PRINCIPAL. Daemon effective-author trusts the verified principal instead of resolving as:. Invalidating existing warrants is a CODE change, not a chain event (warrants ride in a write's auth_warrant, checked at validation time) - no transition window, no re-genesis.
- CORRECTED issuer semantics (D): a self-issued derived cert's iss is the BASE IDENTITY, not the domain. v1's "warrant.rs:189 no change" was a bug; generalized to agent_cert.issuer() == parent.principal.email.
- KEPT cert+warrant separate (C): uniformity across self-signed and future IdP-issued agents; identity/authorization separation; well-built warrant factoring. Warrant stays mandatory+audience-bound for agents; authority = warrant scopes. Collapse only attractive if IdP-issued agents are ruled out.
- NAIVE-RP mitigations (E), 3 layers: MUST-surface AgentResult{acts_as,scopes} on conformant verifiers (strongest); a UNIVERSAL explicit authority field on all certs (open=identity, closed=agent); a SHOULD directive; + the WarrantRequired backstop.
- ANTI-DRIFT decided (F): implement the verification ONCE in browserid-core, sbo-core CALLS it (pin e572cda). sbo-core attribution.rs drops Medium/Large -> Small/Medium.
- REVOCATION pinning DROPPED (G): follow the cert's named status endpoint, fail-open within cache/TTL; chain revocation (base-cert non-renewal) backstops a compromised key. On-chain revocation for SBO = new design (SBO has no prior status object - it defers to expiry).
- Marker (H): verification typ (how to verify) kept distinct from the authority field (what it grants).
- PHASING (J): agent-as-self FIRST (unblocks mingo admin migration + exercises the whole chain), then subaddress-regular + subaddress-agent.

Remaining open questions: OQ-1 status-subject registration at browserid.me before first use; OQ-3 (the one factual pre-impl check) whether a classic primary's identity KEY is stable across base-cert refreshes (stable -> derived agent certs survive/long-lived; rotates -> bounded by base cert, ">=8h base validity" rule); OQ-onchain SBO on-chain revocation object is new design if pursued.


## SPEC v3 (2026-07-17) — OQ-1 + OQ-3 RESOLVED

- OQ-3 RESOLVED: the base identity key ROTATES per login/provision (client evidence: keystore.js:64-70 fresh non-extractable key each generate(); dialog.js:226-253/301-318/440-460 reuse only while cert unexpired; provisioning.js:98-108 fresh per provision; keygen is client-side in the browserid dialog). CONSEQUENCE: derived agent cert is BOUNDED by the base cert - re-issue on base refresh, agent validity <= base validity, hard is_expired on the embedded base cert, ">=8h base validity when minting" rule. UX: self-derived agents expire with the base (~24h) -> periodic re-auth; fine for interactive CLIs (mingo admin), but unattended bots want the IdP-minted path (reinforces decision C). Design treats the key as rotating: correct today, future-proof if keys ever stabilize.
- OQ-1 RESOLVED: as-is needs a server-allocated status idx (StatusRef.idx is a server autoincrement; revoke flips existing rows), BUT validity is already lazy (positive/revoked-only list, absence=valid). DECISION: target FULLY-OFFLINE revocation via 3 small status-service changes - self-derivable idx = wide-truncation hash(subject) (>=64-bit, ideally 128-bit), sparse revoked-set encoding (not the dense MAX(idx) bitmap), and a revoke-by-assertion upsert endpoint (owner assertion binds the subject). DEFER all 3 to PHASE 2 (the browser-RP subaddress cases needing per-agent revocation). PHASE 1 (agent-as-self / mingo admin) relies on CHAIN revocation (base-cert expiry) + SBO on-chain, verifier fail-open on the named endpoint - no new status-service work.

Only OQ-onchain (SBO on-chain revocation object = new design) remains open. Doc bumped to v3.


## OQ-1 refinement (2026-07-17, dan): offline-CAPABLE by design, online-IN-PRACTICE

browserid.me knows about the derived cert REGARDLESS - the per-agent revoke UI lives on browserid.me/account, and you can't list/revoke a cert the server never heard of. So the offline property is about ROBUSTNESS (validity/revocability never DEPEND on a server round-trip; the idx is self-derivable, not server-allocated), not about never calling the server. In practice the client TELLS browserid.me about the derived cert at derivation time so it appears in the /account list + revoke UI - a best-effort/UI concern, not a required allocation step. Self-derivable hashed-idx design unchanged; still deferred to phase 2 (phase 1 uses chain revocation). §6.2.1 + OQ-1 resolution reworded.


## OQ-3 UX pain RESOLVED (phase-2): same-key re-stamping (bean browserid-ng-s5xa)

The ~24h re-issue churn is fixable. The per-refresh key rotation is VESTIGIAL (classic-Persona carryover), not a security choice - no forward-secrecy rationale in code/history; the only documented key rationale is non-extractable custody (e2fi = storage, not rotation). CORRECTION to the OQ-3 framing: "keys rotate" is only a browser-DIALOG convention, NOT a system invariant - the Rust browserid-agent ALREADY keeps a stable key and re-mints (lib.rs:498-511), and nothing keys on key fingerprint (status per-identity-email, replay aud+exp bounded, cert cache per (issuer,email)). Fix is client-only (dialog.js reuse-if-present + present stored pubkey in the primary genKeyPair path); broker certifies whatever pubkey it's given (no broker change); works for classic primaries; safe given e2fi. Phase-2, opt-in/scoped -> global. Phase-1 stays bounded/re-issue-on-refresh; re-stamping makes long-lived derived agents pleasant. Tracked in browserid-ng-s5xa; doc section 5.1.1.
