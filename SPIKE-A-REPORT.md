# SPIKE-A — Direction A: popup bootstrap, login-via-agent-mint

**Verdict: WORKS (mechanic proven in Rust; JS handoff sketched). The entangling
model is clean and the reuse is very high — the agent machinery is ~90% of it.**

Throwaway spike in an isolated worktree. Not pushed.

## What was prototyped

1. **The key mechanic (Rust, real types, passing tests).**
   `browserid-core/tests/spike_a_login_via_mint.rs` (3 tests, green) uses the
   real `provisioning`/`Certificate` types unchanged to show that a single
   `mint` verb, from one `U_cert~P_cert~R` bundle, issues **either**:
   - `name == "@self"` → a **plain user (login) cert** binding the browser's key
     to the human's real email (`!is_agent()`), OR
   - `name == "bot"` → an **agent cert** `bot@domain` attributed to the human
     (`is_agent()`).

   Same verification path, same issuance mechanics — a pure parameter/mode
   difference. Tests also show: (a) after the one bootstrap the browser re-mints
   login certs headlessly with no nav/cookie; (b) a login-only (`@self`)
   credential still cannot mint arbitrary agents (constraint gate holds).

2. **The real broker change (compiles).** `browserid-broker/src/routes/agent.rs`
   `mint()` gained a `LOGIN_SELF` branch: on `@self` it loads the delegator's
   own `Email` record and calls the *existing* `issue_certificate` (plain-user
   path) instead of `ensure_agent_identity`. ~30 lines. Nothing else changed —
   `verify_as_target_idp`, endorsement, status refs, quota all reused as-is.

3. **The popup handoff + JS client shape (sketch).**
   `browserid-broker/static/spike_a_login_sketch.js` — opener uses `WinChan.open`
   to a new top-level `/bootstrap` page; the popup authenticates first-party,
   mints its own `U_cert` via the unchanged `/wsapi/cert_key`, self-signs the
   `P_cert` delegation, and returns `{uCert, pCert, P_priv}` over the WinChan
   `{a:'response'}` channel. The opener then mints login certs via
   `/provision/endorse` + `/provision/mint`. **No certificate crosses
   postMessage — only the delegation.**

## Reused vs new

**Reused (already exists, unchanged):**
- The whole delegation chain: `U_cert~P_cert~R` + endorsement, `RequestBundle::verify`,
  `verify_as_target_idp`, `issue_certificate`, status refs, quotas (core +
  agent.rs + cert.rs).
- `browserid-agent`'s client model (`AgentCredential`, `build_bundle`, `mint`,
  `endorse`) is line-for-line the browser client — the browser literally *is* an
  agent holding a provisioning credential.
- `WinChan.open`/`onOpen` popup channel (include.js), `Keystore` non-extractable
  keys + IndexedDB, and — crucially — the recent same-tab handshake
  (`consent.html` `startSameTabProvision`/`consumePendingProvision`, mingo-ytrs)
  already proves the ITP-safe top-level pattern; its own source note says
  "dialog.js handlePrimaryIdP can adopt it for the login/client-signing path
  later." This spike is that adoption, via a popup instead of same-tab nav.

**New (to build for real):**
- `@self` login mode in `mint` (done here) + a `Constraint` convention allowing
  a login-capable-but-agent-less credential (today `Constraint::validate`
  requires ≥1 name — `@self` satisfies it, so no core change strictly needed).
- A `/bootstrap` top-level page (trimmed dialog.js: login screens + `cert_key`
  call + client-side `P_cert` signing; **delete** genKeyPair/getCert-over-
  postMessage and the hidden `provisioning.js` iframe path).
- Opener-side credential store + headless mint driver (sketch #3).
- Client-side `P_cert` JWS signing in JS (the one genuinely new crypto bit;
  small — EdDSA over a JSON claim set, mirroring `ProvisioningCert::create`).

## Assessment

- **Feasibility: works.** The core mechanic is proven against real types; the
  broker change compiles; the only unproven piece is JS `P_cert` signing, which
  is a small well-understood JWS.
- **Reuse: very high (~90%).** Login collapses onto the agent path; the agent
  crate is a working reference implementation of the browser client.
- **Cleanliness: high.** "Login = provisioning the browser as an agent" makes
  the entanglement *structural*: an IdP cannot serve login without serving
  `/provision/mint`, because login IS a mint. One issuance choke point
  (`issue_certificate`) for humans, browsers-as-agents, and bots.
- **Popup UX: good, one-time.** The interactive popup fires only at bootstrap
  (or after the ~90-day `P_cert` expires); every subsequent login is a silent
  headless mint. Popups can be blocked and must be gesture-initiated — the
  existing WinChan blocked-popup handling and the Arc same-tab fallback
  (consent.html) both already exist to cover this.
- **ITP / 3p-cookie resistance: strong — the whole point.** The interactive step
  is a **top-level, first-party** context (popup on the IdP origin), so its
  session cookie is first-party and ITP-immune, unlike the dead hidden
  cross-origin iframe. After bootstrap there are zero cookies in the loop: mint
  is signature-authenticated HTTP.
- **Effort for a real impl: moderate.** Broker: ~30 lines (done). Core: ~0.
  JS: build `/bootstrap` (largely a subset of dialog.js), delete the iframe
  provisioning path (`provisioning.js`, `provisioning_api.js`, dialog.js
  `handlePrimaryIdP` cert branch), add opener-side JS `P_cert` signing + mint
  driver + credential store. Call it a few days, most of it deletion.

## Blockers / surprises

- **No blockers.** The heavy lifting (delegation chain, endorsement, dual
  issuance path, non-extractable keystore, ITP-safe top-level handshake) was all
  already built for agents/consent. Direction A is mostly *rewiring login onto
  it* plus deleting the iframe cert flow.
- **Surprise (positive):** `consent.html` already ships the ITP-safe top-level
  provisioning handshake and explicitly anticipates the login path adopting it —
  so a same-tab variant of Direction A is even closer to done than the popup
  variant, and the two can share code.
- **Minor design point:** a login-only credential wants a `Constraint` that
  grants `@self` and nothing else. `@self` is not a valid agent handle (`@` is
  illegal), so it can't collide; `Constraint::validate` already accepts it as a
  non-empty name. Clean enough; a dedicated boolean could replace the sentinel
  if preferred.
- **Trust nuance:** the popup hands `P_priv` to the opener. Opener and popup are
  the same IdP origin here, so this is same-origin; if the opener is ever a
  different origin, generate `P` non-extractable inside the popup and never
  export it (hand back only `U_cert~P_cert`, popup keeps `P_priv` — but then the
  opener can't mint, so `P` must live where the mint happens). For login the
  opener IS the mint driver, so same-origin `P_priv` handoff is correct.

## Files

- `browserid-core/tests/spike_a_login_via_mint.rs` — the proven mechanic (3 green tests)
- `browserid-broker/src/routes/agent.rs` — real `@self` login branch in `mint()` (compiles)
- `browserid-broker/static/spike_a_login_sketch.js` — popup handoff + client shape
