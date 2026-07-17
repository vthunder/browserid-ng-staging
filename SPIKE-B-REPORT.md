# SPIKE-B — "Browser is the first agent" via TOP-LEVEL REDIRECT bootstrap

Throwaway spike. Assesses **Direction B**: the interactive identity-proof is a
full-page OAuth-style **redirect** (no hidden iframe, no postMessage cert
flow); it returns a **provisioning credential**; the browser then mints its
login cert **headlessly over HTTP** through the existing agent mint endpoint —
the same endpoint CLIs/bots use.

Shared model across all three spikes: **login = provisioning the browser's
stable key as an agent.** (1) an interactive proof bootstraps a provisioning
credential (a delegation authorizing the browser's key to mint certs for the
user); (2) the browser mints its login/user cert headlessly. This structurally
forces login-implies-agents.

---

## 1. The key mechanic (demonstrated + tested)

**Claim:** one credential + one endpoint issues a **login (user) cert** or an
**agent (delegate) cert**, differing only by a parameter.

Evidence: `browserid-core/tests/spike_b_browser_as_agent.rs` (3 tests, green).
It drives the *real* delegation-chain types the broker and `browserid-agent`
already use:

- The provisioning credential is `U_cert~P_cert` — the exact pair the browser
  builds today in `account.html` (lines 706-713): generate a provisioning key,
  build `ProvisioningCertClaims`, **sign it with the non-extractable identity
  key** (`keystore.js` `sign()`), concatenate `id.cert ~ P_cert`.
- The browser signs a short-lived request with `P_priv` and presents
  `U_cert~P_cert~R` to the IdP. Issuance branches on **one parameter**, the
  request `Action`:
  - `Action::Login` → `Certificate::create(...)` — a **plain user cert** for
    the delegator's **own** email (`dan@mingo.place`), bound to the browser's
    stable key. `is_agent() == false`; verifies under the IdP key like any
    browserid cert, so **RPs need no new machinery**.
  - `Action::Mint` → `Certificate::create_agent(...)` — an **agent cert** for a
    derived, constraint-authorized handle (`ci@mingo.place`) with
    `agent.parent` attribution.

**Code added (minimal, compiles, real):**
- `browserid-core/src/provisioning.rs`: new `Action::Login` variant +
  `ProvisioningRequest::login(domain, agent_pub, ephemeral, key)`. No `name`
  (the subject is the U_cert principal, not a derived handle).
- The test models the broker's `verify_as_target_idp` + `issue_certificate`
  branch with public core APIs (`RequestBundle::verify` is used verbatim by
  `agent::verify_as_target_idp`), keeping it self-contained + runnable.

**Broker wiring sketch** (what a non-spike impl would add to
`browserid-broker/src/routes/agent.rs`, ~30 lines):

```rust
// POST /provision/mint, when verified.request.action == Action::Login:
fn mint_login(state, verified) -> MintResponse {
    // Authorization: the credential must carry the explicit login capability
    // (see §4). NOT implied by an agent-only constraint.
    require_login_capability(&verified.constraint)?;
    let account = user_store.get_user_by_email(&verified.delegator)?;   // the user
    let record  = user_store.get_email(&verified.delegator)?;           // their OWN verified email
    // Reuse issue_certificate UNCHANGED: record.email_type != Agent, so it
    // takes the plain `Certificate::create_with_status` branch already there.
    let cert = issue_certificate(&state.domain, &state.keypair, user_store,
                                 &record, &agent_pubkey_json(agent_key),
                                 verified.request.ephemeral.unwrap_or(false))?;
    MintResponse { success: true, email: record.email, cert }
}
```

Note: `issue_certificate` (cert.rs) **already** issues a plain user cert for a
non-agent `email_record` — the login path needs *no new issuance code*, only a
new front-door branch that resolves the subject to the delegator's own email
instead of a derived handle.

**JS client shape** (browser, headless mint after bootstrap):

```js
// browserKey: the stable NON-EXTRACTABLE key from keystore.js (IndexedDB).
// cred: { delegation: "U_cert~P_cert", provSk } returned by the bootstrap (§2).
async function mintLoginCert(cred, browserKey, idpUrl, idpDomain) {
  const R = { typ:'browserid-provisioning-request-v1', iat:nowS(), exp:nowS()+600,
              action:'login', domain: idpDomain,
              'agent-key': { algorithm:'Ed25519', publicKey: browserKey.publicKeyX } };
  const jws    = await signWithProvKey(cred.provSk, R);          // P_priv signs R
  const bundle = `${cred.delegation}~${jws}`;
  const { endorsement } = await post(`${broker}/provision/endorse`, { request_bundle: bundle });
  const { cert } = await post(`${idpUrl}/provision/mint`, { request_bundle: bundle, endorsement });
  await Keystore.put(idpDomain, userEmail, { privateKey: browserKey.privateKey, cert }); // logged in
}
```

The identical call with `action:'mint'` + a `name` yields an agent cert. Login
and agent-minting are the same code path.

---

## 2. The redirect bootstrap (how the credential comes back)

The bootstrap's job: prove the user interactively **once**, and hand the
browser a `U_cert~P_cert` delegation for its stable key. Two hops, no iframe,
no third-party cookie:

```
Browser (broker origin)                         IdP (its own first-party origin)
──────────────────────────                      ─────────────────────────────────
1. gen/lookup STABLE browser key (keystore.js)
   gen provisioning key P
   stash {browserKey, P, nonce, returnTo}
        PENDING in IndexedDB
2. location.href = IdP/provision_return
        ?ident_pub=<identity pubkey>
        &prov_pub=<P_pub>
        &state=<nonce>
        &return_to=<broker URL>      ───────►  3. user authenticates in the IdP's
                                                  OWN first-party session (password /
                                                  passkey / existing cookie). ITP is
                                                  irrelevant: it's a top-level 1P visit.
                                               4. IdP mints U_cert for identity pubkey,
                                                  signs P_cert (constraint incl. login),
                                                  builds delegation = U_cert~P_cert
                                               5. 302 back to return_to
        ◄──────────────────────────────────────   #delegation=<U~P>&state=<nonce>
6. consumePendingProvision():
   - strip fragment (history.replaceState)
   - match state==nonce; check P_cert.public-key==P_pub
   - store delegation + P + browserKey
7. mint login cert HEADLESSLY via /provision/mint (§1) — no more navigation ever
```

**This is not hypothetical — 90% of it already ships.** `consent.html`
(mingo-ytrs, commit 5759ed6) implements exactly this handshake today, but the
redirect returns a **one-shot cert** in the fragment. Direction B changes only
*what comes back*: a **delegation** (reusable ~90 days) instead of a single
24h cert. Reused verbatim:

- `keystore.js` PENDING store — a non-extractable CryptoKey survives a
  top-level navigation via IndexedDB structured-clone (sessionStorage can't).
- `startSameTabProvision()` — stash pending, `location.href` to the IdP,
  `return await new Promise(()=>{})` to halt.
- `consumePendingProvision()` — fragment parse, immediate
  `history.replaceState` strip, `state` nonce match, pubkey/principal binding
  checks.

**Return-channel choice.** Two viable shapes:
- **(a) fragment-carried delegation** (what mingo-ytrs does for the cert): the
  `U_cert~P_cert` rides back in `#delegation=…`. Simplest, zero extra
  round-trip, never sent to a server (fragment stays client-side). A P_cert is
  ~public anyway (it's in every request bundle), so fragment exposure is
  acceptable. **Recommended.**
- **(b) one-time code**: return `?code=<opaque>&state=<nonce>`; browser POSTs
  the code to `IdP/provision_exchange` to fetch the delegation. Better if the
  delegation ever carried anything sensitive, or to bind delivery to a POST +
  CSRF; costs one HTTP round-trip. The provisioning key `P` is browser-side in
  both cases and never transits either channel.

**Why no third-party cookie / no ITP problem:** the only cookie read is the
IdP's OWN first-party cookie during the top-level `/provision_return` visit —
the same cookie a normal login page reads. There is no embedded third-party
frame, so ITP/CHIPS/storage-partitioning have nothing to block. Contrast
Direction A.1's iframe, which is precisely the ITP-dead path mingo-ytrs was
created to replace.

---

## 3. Reused vs new

**Reused (verbatim / near-verbatim):**
- Whole delegation-chain crypto: `RequestBundle`, `ProvisioningCert`,
  `ProvisioningRequest`, `Endorsement`, `verify()` (signing-time semantics).
- `/provision/endorse` (broker registrar) and `/provision/mint` transport —
  the headless HTTP mint is `browserid-agent`'s exact flow (`lib.rs::mint`).
- `issue_certificate` (cert.rs) — its non-agent branch already emits the plain
  login cert; no issuance code changes.
- `keystore.js` (non-extractable stable key + PENDING staging store) and the
  `consent.html` same-tab redirect handshake (mingo-ytrs) — the entire
  redirect scaffolding exists.
- In-browser delegation signing (`account.html` 706-713).

**New (small):**
- `Action::Login` + `ProvisioningRequest::login()` in core (done here).
- Broker front-door branch `mint_login` (~30 lines, sketch in §1) — resolve
  subject to `verified.delegator`'s own email + a login-capability gate.
- A login-capability marker in the credential (this spike used a `"@self"`
  sentinel name; a real impl adds a typed `Constraint.login: bool`).
- IdP `/provision_return` returns a **delegation** (or code) instead of a cert
  — a variant of the mingo-ytrs return handler.

---

## 4. Report — feasibility & comparison input

**Feasibility: HIGH, with running evidence.** The crypto mechanic is proven
(`spike_b_browser_as_agent.rs`, 3 green tests) on the real core types. The
redirect bootstrap is not speculative — its twin ships today in `consent.html`
(mingo-ytrs). Direction B is essentially "return a delegation, not a cert, from
the existing same-tab handshake, then mint via the existing agent endpoint."

**Reuse of existing agent machinery: near-total.** Login rides the *identical*
`endorse → mint` HTTP path CLIs/bots use; the only genuinely new server code is
a ~30-line front-door branch. This is the strongest structural argument for the
shared model: login and agent-mint are literally one endpoint.

**Cleanliness: high.** One credential, one endpoint, one `Action` parameter.
`issue_certificate`'s existing user/agent branch maps 1:1 onto login/mint. No
postMessage, no iframe, no cross-origin channel to secure — the attack surface
that `provisioning_api.js` spends 30 lines defending (origin pinning, source ==
parent) simply doesn't exist here.

**UX of the redirect bootstrap:**
- *Cost*: one full-page navigation away and back, **once**, at bootstrap
  (≈ every 90 days when the delegation lapses, or on a new device). Every login
  and every agent-mint thereafter is a headless HTTP call — **zero navigation**.
  This is strictly better than any per-login redirect.
- *Session continuity*: the browser origin persists across the hop
  (`return_to` is the broker's own URL); the stable key + any in-flight state
  survive in IndexedDB (non-extractable key structured-clones across the nav —
  already relied on by mingo-ytrs). The visible cost is a top-level page
  transition (flash + back), the familiar OAuth feel.
- *Friction vs A.1*: A.1's iframe is invisible but **dead under ITP**; B's
  redirect is visible but **works**. mingo-ytrs already paid this exact
  trade-off deliberately.

**ITP / third-party-cookie resistance: EXCELLENT.** No embedded frame, no 3P
cookie, no partitioned storage dependency. The only cookie touched is the IdP's
1P cookie on a top-level visit. This is the whole reason the direction exists.

**Implementation effort/size: SMALL.** core: ~25 lines (done). broker:
~30-line branch + a typed login-capability flag. IdP return page: a variant of
the shipping mingo-ytrs handler returning a delegation. JS: reuse
`startSameTabProvision`/`consumePendingProvision` with a delegation payload +
the `mintLoginCert` helper (§1). No RP/verifier changes.

**Blockers / surprises:**
- **Login capability must be explicit (the central security point).** A
  provisioning credential that can mint a *login* cert for the user's own
  identity is a full login credential — strictly more powerful than an
  agent-only credential (which can only mint derived, attributable handles). If
  login were implied by any provisioning cert, "provision an agent" would
  silently equal "grant login-as-me." The spike enforces this with an explicit
  capability marker (`"@self"` sentinel; test `login_refused_without_the_
  login_capability` proves an agent-only credential is refused). A real impl
  wants a typed `Constraint.login: bool` and clear consent copy at bootstrap
  ("this browser may sign in as you") distinct from agent grants.
- **Credential lifetime = login lifetime.** A 90-day delegation means a 90-day
  silent-login window bounded only by revoking the P_cert (registrar stops
  endorsing) — acceptable given the existing status-list revocation, but it
  shifts "logout everywhere" to "revoke the provisioning cert," which must be
  a first-class, discoverable action.
- **Fragment vs code** (§2): fragment is simplest and matches mingo-ytrs;
  choose the one-time code only if the return payload ever needs POST/CSRF
  binding.
- **No true blocker found.** The pieces exist; the work is assembly + one
  security gate, not invention.

**Bottom line:** Direction B is the lowest-effort, highest-reuse, most
ITP-durable of the redirect-vs-iframe options — because its redirect half
already ships (mingo-ytrs) and its mint half already ships (browserid-agent).
The one thing to get right is making login capability an explicit, consented
grant rather than a side effect of provisioning.
