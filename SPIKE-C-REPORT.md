# SPIKE C — iframe-relies-on-HTTP-mint (login mints through the agent endpoint)

**Throwaway spike.** Prototype + assessment of DIRECTION C of "make the human's
browser the first agent": keep the existing interactive AUTH ceremony, but move
the CERT-ISSUANCE step onto the agent mint endpoint (`/provision/mint`), so an
IdP's login now structurally depends on the mint endpoint.

## The shared model

Login should mint its cert through the AGENT endpoint, so that supporting login
STRUCTURALLY requires supporting agents. Direction C is the minimal variant:
keep the ITP-vulnerable auth ceremony untouched; only re-route where the login
cert is issued.

## 1. The concrete change (demonstrable mechanic)

Today two code paths issue a login cert:

- **Secondary / fallback (broker-as-IdP):** `dialog.js::generateCertificate()`
  → `POST /wsapi/cert_key` (session-authed) → cert. This is the path Direction C
  actually re-wires.
- **Primary (third-party IdP):** the hidden iframe (`provisioning.js` +
  `provisioning_api.js`) drives `beginProvisioning → genKeyPair →
  registerCertificate` over postMessage; the IdP page's own server mints and
  relays the cert back.

**What the spike changes:**

- **`browserid-broker/src/routes/agent.rs`** — `/provision/mint` becomes the
  single cert-issuance front door. Its body is now an untagged enum `MintBody`:
  - `Delegated { request_bundle, endorsement }` — the agent delegation chain,
    **unchanged**.
  - `Login { email, pubkey, ephemeral, csrf }` — a **session-authenticated login
    self-mint**. `mint_login()` proves the session owns `email` and calls the
    same `issue_certificate()` core `/wsapi/cert_key` uses. Dispatch is purely by
    JSON shape.
- **`browserid-broker/static/dialog.js`** — one line: `certKey:
  '/wsapi/cert_key'` → `certKey: '/provision/mint'`. The dialog's existing
  `generateCertificate()` body (`{email, pubkey, ephemeral}`, csrf auto-injected
  by `apiCall`) is already exactly the `Login` shape, so **login now flows
  through the agent mint endpoint** with no other JS change.
- **`browserid-broker/static/provisioning.js`** — the primary-IdP iframe path:
  documented the intended collapse (delete `genKeyPair` + `registerCertificate`,
  mint over HTTP instead) and added a real `httpMintAfterAuth()` sketch method
  that generates the key and POSTs the `Login` shape to
  `<idp>/provision/mint`. Left functionally in place because of the blocker
  below.

**Evidence it works:** `browserid-broker` compiles; new unit test
`spike_c_tests::mint_body_dispatches_on_shape` passes (proves the Login vs
Delegated dispatch, incl. `csrf` default); full broker suite **133 passed / 0
failed** — the delegation-chain agent path is untouched.

## 2. What credential the auth-ceremony yields, and how the two connect

The interactive auth ceremony (password sign-in, or the primary iframe's
`beginProvisioning`/`auth_with_assertion`) yields a **broker session cookie**.
That session IS the provisioning credential for the login self-mint: the
credentialed `fetch('/provision/mint', {credentials:'include'})` carries it,
`mint_login` resolves it to an account, checks the account owns `email`, and
issues the cert. Auth (iframe/session) and issuance (agent endpoint) connect
through the session cookie — no warrant, no delegation chain for the human's own
login.

## 3. REUSED vs NEW — quantified (this is the smallest variant)

| | |
|---|---|
| **Reused as-is** | `issue_certificate()`, session/CSRF helpers, `dialog.js::generateCertificate` body, the whole iframe auth ceremony, `MintResponse` |
| **New server code** | `MintBody` enum + `mint_login()` (~40 lines) + `Cookies` extractor on `mint` |
| **New/changed JS** | 1-line endpoint swap in `dialog.js`; doc + optional `httpMintAfterAuth()` sketch in `provisioning.js` |
| **Net functional diff** | ~50 lines Rust, 1 line JS |

No new endpoint, no new crypto, no wire-format change, no DB migration. This is
by far the smallest of the three directions.

## Assessment (comparison input)

- **Feasibility:** High, with evidence — compiles, tests green, the demonstrable
  (broker-as-IdP) login path works end-to-end through `/provision/mint`.
- **Reuse:** Highest of the three. Reuses `issue_certificate`, the session model,
  and the existing dialog body verbatim; the auth ceremony is byte-for-byte
  unchanged.
- **Cleanliness (honest):** Mixed. It genuinely entangles login+agents at one
  mint choke point, but it keeps the dying hidden iframe, and it slightly
  overloads `/provision/mint` with an untagged-enum body (agent delegation vs
  session login) — two different auth models behind one URL. `cert_key` survives
  only as a shared core, so there's now a vestigial endpoint.
- **UX:** Unchanged from today — same screens, same taps, same latency. Nothing
  the user sees moves.
- **ITP / third-party-cookie resistance:** Does **NOT** fix it. The self-mint is
  session-cookie-authed; for a *third-party* primary IdP the credentialed fetch
  is a cross-site cookie'd request — the same ITP surface the iframe already dies
  on. So the HTTP-mint replacement is only actually reachable when the mint
  target is the SAME origin as the dialog (the broker/fallback path). This spike
  entangles login+agents but buys **zero** ITP improvement.
- **Effort / size:** Smallest (~50 LOC).
- **Blockers / surprises:**
  1. **The real blocker:** `/provision/mint`'s login mode is session-authed;
     third-party primary IdPs can't be reached that way cross-site. A genuine
     third-party mint would need a delegation-chain bundle (`U_cert~P_cert~R` +
     endorsement) instead of a session — which is a much bigger change and
     defeats "smallest diff."
  2. **Semantic mismatch surfaced:** `/provision/mint`'s native job is to mint
     **agent** identities (`<name>@<domain>`, `EmailType::Agent`, warrant-gated
     certs). A login needs a **plain** cert for the user's own email. So "reusing"
     the endpoint is really adding a second, session-authed code path beside it —
     the entanglement is at the URL, not deep in the logic.
  3. Untagged serde ordering: `Delegated` must be tried before `Login` (a Login
     body lacks `request_bundle`, so it correctly falls through) — verified by
     test.
