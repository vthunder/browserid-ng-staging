/*
 * SPIKE-A (throwaway sketch, not wired): DIRECTION A —
 * "make the human's browser the first agent."
 *
 * Login = provisioning the BROWSER'S key as an agent. The interactive proof
 * happens in a POPUP (top-level, first-party, ITP-safe — reusing WinChan). The
 * popup returns a PROVISIONING CREDENTIAL to the opener; the browser then mints
 * its login cert HEADLESSLY via the agent mint endpoint. The hidden-iframe cert
 * flow (provisioning_api.js genKeyPair/getCert over postMessage) is REMOVED.
 *
 * This file is a code shape, not a build target. It leans on the existing:
 *   - WinChan.open / WinChan.onOpen (include.js) for the popup channel
 *   - Keystore (common/js/keystore.js) for non-extractable CryptoKeys + IndexedDB
 *   - /wsapi/cert_key (cert.rs) for the popup's own U_cert issuance
 *   - /provision/endorse + /provision/mint (agent.rs) for headless minting
 */

'use strict';

const LOGIN_SELF = '@self'; // must match agent.rs::LOGIN_SELF

// ===========================================================================
// OPENER SIDE (the RP-facing shim, i.e. what include.js does on `navigator.id
// .request()`). Replaces "open dialog → get assertion over postMessage" with
// "have a provisioning credential → mint login cert headlessly → assertion".
// ===========================================================================

async function login(idpOrigin, rpAudience) {
  let cred = await Credential.load(idpOrigin);      // {P_priv, uCert, pCert} from IndexedDB
  if (!cred || cred.expired()) {
    cred = await bootstrapViaPopup(idpOrigin);      // STEP 1: interactive, ONCE
  }
  // STEP 2: headless. No popup, no iframe, no 3p cookie — pure fetch POSTs.
  const loginKey = await Keystore.generate();       // non-extractable per-login cert key
  const cert = await mint(cred, LOGIN_SELF, loginKey.publicKeyX);
  return makeAssertion(loginKey.privateKey, cert, rpAudience);
}

// ---------------------------------------------------------------------------
// STEP 1 — POPUP BOOTSTRAP (the only interactive step, ITP-safe)
// ---------------------------------------------------------------------------
//
// WinChan.open spawns a top-level popup on the IdP origin. Inside it the user
// authenticates against a FIRST-PARTY session cookie (unlike the dead hidden
// cross-origin iframe). The popup mints a U_cert for a fresh browser identity
// key and self-signs the P_cert delegation, then returns {uCert, pCert, PjwkPriv}
// through the WinChan response channel ({a:'response', d:...}).
function bootstrapViaPopup(idpOrigin) {
  return new Promise((resolve, reject) => {
    WinChan.open({
      url: idpOrigin + '/bootstrap',           // NEW top-level page (replaces /sign_in cert path)
      relay_url: idpOrigin + '/relay',
      window_name: '__browserid_bootstrap',
      window_features: 'menubar=0,location=1,resizable=1,scrollbars=1,width=700,height=375',
      params: { method: 'get', params: {} }
    }, async (err, r) => {
      if (err) return reject(err);
      // r = { uCert, pCert, provisioningKeyJwk }  (P_priv arrives ONCE, then is
      // re-imported non-extractable and the raw jwk is dropped). Alternative:
      // generate P inside the popup non-extractable and hand back only a wrapped
      // key — but a jwk over the same-origin-opener channel is acceptable here.
      const P = await Keystore.importProvisioningKey(r.provisioningKeyJwk);
      const cred = new Credential(idpOrigin, P, r.uCert, r.pCert);
      await cred.save();                        // IndexedDB, survives sessions
      resolve(cred);
    });
  });
}

// ---------------------------------------------------------------------------
// STEP 2 — HEADLESS MINT (login OR agent — same endpoint, `name` differs)
// ---------------------------------------------------------------------------
async function mint(cred, name, agentPubJson) {
  const request = await cred.signMintRequest(name, agentPubJson); // R signed by P_priv
  const bundle = cred.uCert + '~' + cred.pCert + '~' + request;   // U_cert~P_cert~R
  const endorsement = await postJson(cred.broker + '/provision/endorse',
                                     { request_bundle: bundle }).then(x => x.endorsement);
  const out = await postJson(cred.idp + '/provision/mint',
                             { request_bundle: bundle, endorsement });
  return out.cert; // login mode → plain user cert; named → agent cert
}

// login uses the same call with a real handle → an AGENT (delegate) cert:
//   const agentKey = await Keystore.generate();
//   const agentCert = await mint(cred, 'bot', agentKey.publicKeyX);

// ===========================================================================
// POPUP SIDE (served at /bootstrap on the IdP origin; top-level, first-party).
// The counterpart to dialog.js, minus all cert-over-postMessage machinery.
// ===========================================================================
async function bootstrapPageMain() {
  WinChan.onOpen(async (origin, args, cb) => {
    // 1. Interactive: existing login UI drives a first-party session cookie.
    await interactiveSignIn();                       // reuse dialog.js login screens
    const email = currentUserEmail();

    // 2. Mint a U_cert for a FRESH browser identity key via the ordinary,
    //    session-authenticated cert endpoint (no change to cert.rs needed).
    const U = await Keystore.generate();
    const uCert = await postJson('/wsapi/cert_key', {
      email, pubkey: U.publicKeyX, csrf: sessionCsrf()
    }).then(x => x.cert);

    // 3. Self-sign the P_cert delegation client-side: U_priv signs
    //    "P_pub may provision for `email`", constraint grants @self (+ handles).
    const P = await Keystore.generate();
    const pCert = await signProvisioningCert(U.privateKey, {
      iss: email, publicKey: P.publicKeyX,
      constraint: { names: [LOGIN_SELF] }            // add handles to also mint agents
    });

    // 4. Return the provisioning credential to the opener (same-origin opener;
    //    WinChan pins origin). NOTE: no certificate for the RP crosses here —
    //    only the delegation. The opener mints login certs itself, headlessly.
    cb({ uCert, pCert, provisioningKeyJwk: await Keystore.exportOnce(P) });
  });
}

/* Whatever helpers (postJson, makeAssertion, signProvisioningCert, Credential,
 * interactiveSignIn) are elided — see the report for what is REUSED vs NEW. */
