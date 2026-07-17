/*
 * BrowserID-NG Dialog Logic
 * Based on Mozilla Persona (MPL 2.0) - simplified and modernized
 */

(function() {
  'use strict';

  // Set storageCheck bit so communication_iframe knows localStorage is accessible
  // (see issue #3905 in original browserid)
  try {
    localStorage.storageCheck = "true";
  } catch (e) {
    // localStorage may not be available (iOS privacy mode, etc.)
  }

  // State
  let state = {
    email: null,
    origin: null,
    callback: null,
    winchanCallback: null,  // WinChan response callback
    winchanHandle: null,    // WinChan handle with detach() method
    emails: [],
    derived: {},  // subordinate identity -> controlling parent email (mingo-cm8z)
    selectedEmail: null,
    newEmail: null,  // Email being added to account
    pendingAddressInfo: null,  // Stored addressInfo for transition flows
    acceptedFallbacks: null,   // RP's accepted fallback IdPs (spec §8.1); null = default {this broker}
    brokerDomain: null,        // this broker's own issuer domain (from session_context)
    externalFallback: null,    // the external fallback IdP we're routing through (apgv), if any
    sboSign: false,  // RP requested the SBO typed-signing capability
    pendingAssertion: null,  // Assertion held while showing the SBO consent screen
    provisionEmail: null  // RP asked to provision/sign in a SPECIFIC identity (skip the chooser)
  };

  // API endpoints (relative to current origin)
  const API = {
    sessionContext: '/wsapi/session_context',
    stageUser: '/wsapi/stage_user',
    completeUserCreation: '/wsapi/complete_user_creation',
    authenticate: '/wsapi/authenticate_user',
    listEmails: '/wsapi/list_emails',
    // SPIKE C: login mints its cert through the AGENT endpoint. The dialog no
    // longer calls /wsapi/cert_key — it POSTs the session-authed "Login" shape
    // to /provision/mint, the same front door headless agents mint through. So
    // supporting email login now structurally requires the mint endpoint.
    certKey: '/provision/mint',
    stageReset: '/wsapi/stage_reset',
    completeReset: '/wsapi/complete_reset',
    logout: '/wsapi/logout',
    addressInfo: '/wsapi/address_info',
    stageEmail: '/wsapi/stage_email',
    completeEmailAddition: '/wsapi/complete_email_addition'
  };

  // DOM elements
  const screens = {
    loading: document.getElementById('loading'),
    email: document.getElementById('email-screen'),
    password: document.getElementById('password-screen'),
    create: document.getElementById('create-screen'),
    verify: document.getElementById('verify-screen'),
    resetEmail: document.getElementById('reset-email-screen'),
    resetPassword: document.getElementById('reset-password-screen'),
    pickEmail: document.getElementById('pick-email-screen'),
    addEmail: document.getElementById('add-email-screen'),
    addEmailVerify: document.getElementById('add-email-verify-screen'),
    setPassword: document.getElementById('set-password-screen'),
    primaryTransition: document.getElementById('primary-transition-screen'),
    primaryAuthContinue: document.getElementById('primary-auth-continue-screen'),
    sboConsent: document.getElementById('sbo-consent-screen'),
    success: document.getElementById('success-screen'),
    error: document.getElementById('error-screen')
  };

  // Screens where the FedCM "auto sign-in next time" checkbox belongs — the
  // ones that complete a sign-in and return an assertion.
  const FEDCM_OPTIN_SCREENS = { pickEmail: 1, password: 1, verify: 1 };

  // The checkbox lives outside the screen cards in markup; each .screen is
  // absolutely-positioned, so we MOVE the one checkbox element into the active
  // sign-in screen's .content so it's actually visible inside the card.
  function placeFedcmOptin(screenId) {
    const row = document.getElementById('fedcm-optin-row');
    if (!row || !state.fedcm) return;
    if (FEDCM_OPTIN_SCREENS[screenId]) {
      const content = screens[screenId] && screens[screenId].querySelector('.content');
      if (content) { content.appendChild(row); row.style.display = ''; }
    } else {
      row.style.display = 'none';
    }
  }

  // Screen management
  function showScreen(screenId) {
    Object.values(screens).forEach(s => s.classList.remove('active'));
    screens[screenId].classList.add('active');
    placeFedcmOptin(screenId);
  }

  function showError(message) {
    const errorEl = document.querySelector('.error-message');
    if (errorEl) {
      errorEl.textContent = message;
    } else {
      console.error('Error (no error element):', message);
    }
    showScreen('error');
  }

  // API helpers
  async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
      method,
      headers: {},
      credentials: 'include'
    };

    if (body) {
      // State-changing wsapi endpoints require the session's CSRF token.
      // Fetched fresh per call: cheap for a login dialog, never stale
      // across the auth transitions that rotate the session.
      if (method === 'POST' && !('csrf' in body)) {
        try {
          const ctx = await (await fetch(API.sessionContext, { credentials: 'include' })).json();
          if (ctx.csrf_token) body = { ...body, csrf: ctx.csrf_token };
        } catch {}
      }
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    const response = await fetch(endpoint, options);
    const data = await response.json();

    if (!response.ok && !data.success) {
      throw new Error(data.reason || 'Request failed');
    }

    return data;
  }

  // Normalize the RP's acceptedFallbacks argument (spec §8.1): null/absent →
  // null (default policy applies); otherwise an array of lowercased issuer
  // domains (an explicit empty array means "primaries only").
  function normalizeAcceptedFallbacks(v) {
    if (v == null) return null;
    if (!Array.isArray(v)) v = [v];
    return v.map(s => String(s).trim().toLowerCase()).filter(Boolean);
  }

  // Whether this broker's own fallback (its `domain`) is acceptable to the RP.
  // Default (no argument) = {this broker}, so email sign-in works as today; an
  // explicit list must name this broker's domain, else the RP declined it.
  // Enforcement is still the RP's verifier (spec §6.1); this is fail-fast UX.
  function brokerFallbackAccepted() {
    if (!state.acceptedFallbacks) return true; // default {this broker}
    const dom = (state.brokerDomain || location.hostname).toLowerCase();
    return state.acceptedFallbacks.indexOf(dom) !== -1;
  }

  // The first accepted fallback IdP that is an EXTERNAL service (not this
  // broker) — the one to route email verification through (spec §8.1, apgv).
  function firstExternalAcceptedFallback() {
    if (!state.acceptedFallbacks) return null;
    const dom = (state.brokerDomain || location.hostname).toLowerCase();
    return state.acceptedFallbacks.find(f => f && f !== dom) || null;
  }

  // Route a no-primary email through an RP-accepted EXTERNAL fallback IdP
  // (apgv). The fallback implements the primary-IdP interface, so we drive its
  // /provision (+ interactive /auth SMTP) exactly like a primary and return the
  // fallback-issued cert's assertion to the RP. This broker is only the
  // mediator/keystore here — it never vouches for the email.
  async function handleExternalFallback(email, fallbackDomain) {
    state.externalFallback = fallbackDomain;
    document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
    await fallbackProvisionAndReturn(email, fallbackDomain, true);
  }

  async function fallbackProvisionAndReturn(email, fallbackDomain, allowAuth) {
    showScreen('loading');
    try {
      const base = 'https://' + fallbackDomain;
      const doc = await (await fetch(base + '/.well-known/browserid')).json();
      const provUrl = base + (doc.provisioning || '/provision');
      const authUrl = base + (doc.authentication || '/auth');
      let result;
      try {
        result = await tryPrimaryProvisioning(email, provUrl, authUrl);
      } catch (e) {
        if (e && e.needsAuth && allowAuth) {
          // No email cookie at the fallback yet — run its interactive /auth
          // (SMTP), then this same routine retries provisioning on return.
          sessionStorage.setItem('browserid_pending_fallback', fallbackDomain);
          redirectToPrimaryAuth(email, e.authUrl || authUrl);
          return;
        }
        throw (e instanceof Error ? e : new Error((e && e.reason) || 'provisioning failed'));
      }
      // Fallback cert obtained. Cache it locally and return an RP assertion.
      // No /wsapi/auth_with_assertion: this broker isn't the issuer, so it holds
      // no account session for a fallback identity.
      const expiresAt = Date.now() + (5 * 60 * 1000);
      await storeEmailKeypair(email, result.keypair.publicKey, result.keypair.privateKey, result.certificate);
      const rpAssertion = await createAssertionFromPrimary(
        result.keypair.privateKey, result.certificate, state.origin, expiresAt);
      storeLoggedInState(state.origin, email);
      state.email = email;
      returnAssertion(rpAssertion);
    } catch (e) {
      showError('Sign-in via ' + fallbackDomain + ' failed: ' + (e.message || e));
    }
  }

  // Check email address info (type, state, primary IdP URLs)
  async function checkEmail(email) {
    // A lookup failure must NOT be silently treated as "new user" — doing so routed
    // existing/primary emails into the create-account flow and produced a confusing
    // "email already exists" 409. Surface the error so the caller can show it and let
    // the user retry. A genuinely-new email still returns 200 with state:"unknown".
    const response = await fetch(`${API.addressInfo}?email=${encodeURIComponent(email)}`);
    if (!response.ok) {
      throw new Error(`couldn't look up this email (${response.status}) — please try again`);
    }
    return await response.json();
  }

  // Generate keypair and get certificate
  async function generateCertificate(email) {
    // Generate Ed25519 keypair
    const keyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      false, // non-extractable (e2fi)
      ['sign', 'verify']
    );

    // Export public key
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    // Request certificate from broker
    const certResponse = await apiCall(API.certKey, 'POST', {
      email: email,
      pubkey: {
        algorithm: 'Ed25519',
        publicKey: publicKeyJwk.x
      },
      ephemeral: false
    });

    return {
      certificate: certResponse.cert,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  }

  // Create assertion
  async function createAssertion(privateKey, certificate, audience, expiresAt) {
    // Assertion payload
    const payload = {
      aud: audience,
      exp: expiresAt
    };

    // Sign the assertion
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
    const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '');
    const message = `${headerB64}.${payloadB64}`;

    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      privateKey,
      encoder.encode(message)
    );

    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const assertion = `${message}.${signatureB64}`;

    // Combine certificate and assertion
    return `${certificate}~${assertion}`;
  }

  // Store logged-in state in localStorage for communication_iframe
  // This mirrors what BrowserID.Storage.site.set does
  function storeLoggedInState(origin, email) {
    try {
      const siteInfo = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      siteInfo[origin] = siteInfo[origin] || {};
      siteInfo[origin].logged_in = email;
      siteInfo[origin].email = email;
      localStorage.setItem('siteInfo', JSON.stringify(siteInfo));
    } catch (e) {
      console.warn('Failed to store logged-in state:', e);
    }
  }

  // Get stored email keypair and certificate
  // Returns { pub, priv, cert } or null if not found
  async function getStoredEmailKeypair(email) {
    try {
      // Non-extractable keys live in IndexedDB (e2fi). Return a fresh cert
      // whose issuer THIS RP accepts (§8.1); multiple issuers coexist (apgv).
      const recs = await Keystore.forEmail(email);
      for (const rec of recs) {
        if (rec.privateKey && rec.cert && !isCertExpired(rec.cert) && storedCertAcceptable(email, rec.cert)) {
          return rec; // { issuer, email, publicKeyX, privateKey: CryptoKey, cert }
        }
      }
      return null;
    } catch (e) {
      console.warn('Failed to get stored email keypair:', e);
      return null;
    }
  }

  // Check if a certificate is expired
  // Certificate is JWT format: header.payload.signature
  // The `iss` of a cert JWS, or null if unparseable.
  function certIssuer(cert) {
    try {
      const parts = cert.split('.');
      if (parts.length !== 3) return null;
      return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))).iss || null;
    } catch (e) { return null; }
  }

  // Whether a cached cert may be reused at this RP (spec §8.1): a primary cert
  // (iss == the email's own domain) always; a fallback cert only if the RP
  // accepts that issuer.
  function storedCertAcceptable(email, cert) {
    const iss = (certIssuer(cert) || '').toLowerCase();
    if (!iss) return false;
    const dom = (email.split('@')[1] || '').toLowerCase();
    if (iss === dom) return true; // primary for its own domain
    if (!state.acceptedFallbacks) {
      return iss === (state.brokerDomain || location.hostname).toLowerCase();
    }
    return state.acceptedFallbacks.indexOf(iss) !== -1;
  }

  function isCertExpired(cert) {
    try {
      const parts = cert.split('.');
      if (parts.length !== 3) return true;

      // Decode payload (base64url)
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      const exp = payload.exp;

      if (!exp) return true;

      // exp is in seconds (Unix timestamp)
      const now = Math.floor(Date.now() / 1000);
      return now >= exp;
    } catch (e) {
      console.warn('Failed to check cert expiration:', e);
      return true; // Assume expired on error
    }
  }

  // Create assertion from stored keypair and certificate
  // This is used when we have a valid stored cert from a primary IdP
  async function createAssertionFromStored(email, stored) {
    try {
      const audience = state.origin;
      const expiresAt = Date.now() + (5 * 60 * 1000); // 5 minutes

      // Sign with the non-extractable private key handle straight from the
      // keystore (e2fi) — no JWK, no import.
      const assertion = await createAssertionFromPrimary(
        stored.privateKey,
        stored.cert,
        audience,
        expiresAt
      );

      storeLoggedInState(audience, email);
      state.email = email;
      returnAssertion(assertion);
    } catch (e) {
      showError('Failed to create assertion: ' + e.message);
    }
  }

  // Handle email chosen - implements the full state machine from original browserid
  // See: browserid/resources/static/common/js/user.js getAssertion()
  // See: browserid/resources/static/dialog/js/misc/state.js email_chosen handler
  // Subordinate-identity substitution (mingo-cm8z). A derived identity (e.g. a
  // minted <handle>@issuer) cannot authenticate to its OWN issuer — the issuer
  // mints it but requires a fresh proof of the controlling parent. So when logging
  // INTO the issuer, we authenticate the parent and deliver ITS assertion instead
  // of completing with the subordinate's cached cert. For every OTHER relying
  // party the subordinate is a first-class identity (returns null → proceed
  // normally, revealing nothing about the parent).
  //
  // Returns the parent email to substitute, or null. `parent_of` is session-gated
  // and scoped to our own emails, so the mapping never leaks. Skipped when the RP
  // explicitly asked to provision THIS identity (state.provisionEmail) — that's a
  // deliberate request to custody the subordinate's own cert (e.g. mingo minting
  // <handle>@mingo.place after the parent already authenticated), not a user
  // choosing it to log in.
  async function maybeSubstituteParent(email) {
    if (state.provisionEmail) return null;
    let rpHost = null;
    try { rpHost = new URL(state.origin).hostname.toLowerCase(); } catch (e) { return null; }
    const emailDomain = (email.split('@')[1] || '').toLowerCase();
    if (!rpHost || emailDomain !== rpHost) return null;
    try {
      const pj = await apiCall(`/wsapi/parent_of?email=${encodeURIComponent(email)}`);
      return (pj && pj.parent_email) ? pj.parent_email : null;
    } catch (e) {
      // Not subordinate, not our email, or not signed in → no substitution.
      return null;
    }
  }

  /// A password-less account (created via a primary identity) signing in
  /// with a broker-verified email. Setting a password requires proof of
  /// control: signed in, the session is the proof (set it directly); signed
  /// out, the reset flow IS that proof — emailed code, then the password.
  /// Never show a bare set-password form to a signed-out visitor (the server
  /// would 401 it anyway).
  async function handleNoPasswordTransition(email) {
    state.email = email;
    document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
    let authenticated = false;
    try { authenticated = (await apiCall(API.sessionContext)).authenticated; } catch {}
    if (authenticated) {
      showScreen('setPassword');
      return;
    }
    await apiCall(API.stageReset, 'POST', { email });
    showScreen('resetPassword');
  }

  async function handleEmailChosen(email, _substituted) {
    showScreen('loading');

    try {
      // 0. Subordinate-identity substitution (mingo-cm8z) — see maybeSubstituteParent.
      if (!_substituted) {
        const parent = await maybeSubstituteParent(email);
        if (parent) return await handleEmailChosen(parent, true);
      }

      // 1. Check for valid stored cert/key (like storedID.priv check in user.js:1338-1344)
      //    Reuse a cached cert only if its issuer is acceptable to this RP
      //    (spec §8.1): a primary cert (iss == email domain) always is; a
      //    broker/fallback cert only if the RP accepts this broker.
      const stored = await getStoredEmailKeypair(email);
      if (stored && stored.privateKey && stored.cert && !isCertExpired(stored.cert)) {
        if (storedCertAcceptable(email, stored.cert)) {
          return await createAssertionFromStored(email, stored);
        }
        // Not acceptable here — fall through to re-verify via an accepted path.
      }

      // 2. No valid stored cert - get addressInfo from server (like user.js:1347)
      const addressInfo = await checkEmail(email);

      // 3. Handle based on type and state (like state.js:400-476)

      if (addressInfo.type === 'primary') {
        // Primary email without valid cert - provision from IdP (state.js:429-434)
        return await handlePrimaryIdP(email, addressInfo);
      }

      // Everything below is secondary — this broker acts as the fallback IdP.
      // Fail fast if the RP didn't list this broker in acceptedFallbacks
      // (spec §8.1), rather than verifying and getting rejected at the RP.
      if (!brokerFallbackAccepted()) {
        const fb = firstExternalAcceptedFallback();
        if (fb) return await handleExternalFallback(email, fb);
        const dom = state.brokerDomain || location.hostname;
        showError('This site doesn’t accept email sign-in via ' + dom +
          '. Use an email whose domain is its own identity provider.');
        return;
      }

      if (addressInfo.state === 'transition_to_secondary') {
        // Was primary, now secondary - need password + verification (state.js:437-447)
        // For now, show authenticate screen to get password
        state.email = email;
        document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
        showScreen('login');
        return;
      }

      if (addressInfo.state === 'transition_no_password') {
        // Account without a password (ex-primary email, or a secondary on a
        // primary-created account) — prove control, then set one.
        await handleNoPasswordTransition(email);
        return;
      }

      if (addressInfo.state === 'unverified') {
        // Email not verified - need to re-verify (state.js:452-455)
        // Stage re-verification
        await apiCall(API.stageEmail, 'POST', { email });
        state.email = email;
        document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
        showScreen('verify');
        return;
      }

      // Secondary, known, verified - check authentication level (state.js:457-472)
      // Then generate assertion from broker
      if (addressInfo.state === 'known') {
        // Can issue new cert from broker
        return await completeSignIn(email);
      }

      // Unknown state - shouldn't happen for a selected email
      showError('Cannot sign in with this email (unknown state: ' + addressInfo.state + ')');

    } catch (e) {
      showError('Failed to sign in: ' + e.message);
    }
  }

  // Store email keypair and certificate for silent assertions
  // This mirrors what BrowserID.Storage.addEmail does
  async function storeEmailKeypair(email, publicKey, privateKey, certificate) {
    try {
      // Store the NON-EXTRACTABLE private key handle in IndexedDB (e2fi). Only
      // the public key is exported (for reference); the private bytes never
      // touch JS. Keyed by the cert's issuer so multiple issuers coexist (apgv).
      const pubJwk = await crypto.subtle.exportKey('jwk', publicKey);
      const issuer = certIssuer(certificate) || 'default';
      await Keystore.put(issuer, email, {
        privateKey: privateKey,
        publicKeyX: pubJwk.x,
        cert: certificate
      });
    } catch (e) {
      console.warn('Failed to store email keypair:', e);
    }
  }

  // Try to provision certificate from primary IdP
  async function tryPrimaryProvisioning(email, provUrl, authUrl) {
    return new Promise((resolve, reject) => {
      BrowserID.Provisioning.start(
        provUrl,
        email,
        function onSuccess(result) {
          resolve(result);
        },
        function onFailure(reason) {
          // Check if this is an authentication issue or another error
          const reasonLower = (reason || '').toLowerCase();
          const isAuthError = reasonLower.includes('not authenticated') ||
                              reasonLower.includes('unauthenticated') ||
                              reasonLower.includes('login required') ||
                              reasonLower.includes('authentication required');

          if (isAuthError) {
            // User needs to authenticate with IdP
            reject({ needsAuth: true, authUrl: authUrl, reason: reason });
          } else {
            // Other error (cert_key failure, email mismatch, etc.)
            reject(new Error(reason || 'Provisioning failed'));
          }
        }
      );
    });
  }

  // Handle primary IdP flow
  async function handlePrimaryIdP(email, addressInfo) {
    showScreen('loading');

    try {
      // Try provisioning first
      const result = await tryPrimaryProvisioning(email, addressInfo.prov, addressInfo.auth);

      const expiresAt = Date.now() + (5 * 60 * 1000);

      // First assertion: audience = broker (to prove email ownership to browserid)
      const brokerAudience = window.location.origin;
      const brokerAssertion = await createAssertionFromPrimary(
        result.keypair.privateKey,
        result.certificate,
        brokerAudience,
        expiresAt
      );

      // Authenticate with broker to establish session
      await apiCall('/wsapi/auth_with_assertion', 'POST', {
        assertion: brokerAssertion,
        ephemeral: false
      });

      // Store keypair for future use
      await storeEmailKeypair(
        email,
        result.keypair.publicKey,
        result.keypair.privateKey,
        result.certificate
      );

      // Record a derived/subordinate identity's parent (mingo-cm8z). The IdP
      // supplied `subordinate_to` privately over the provisioning channel (never
      // in the cert). Both this email and the parent are now in the account (the
      // auth_with_assertion above linked this one), so set_parent will accept it.
      // Non-fatal: a failure just means the substitution UX won't kick in yet.
      if (result.metadata && result.metadata.subordinate_to) {
        try {
          await apiCall('/wsapi/set_parent', 'POST', {
            email: email,
            parent_email: result.metadata.subordinate_to
          });
        } catch (e) {
          console.warn('set_parent failed (non-fatal):', e.message);
        }
      }

      // Second assertion: audience = RP (to return to relying party)
      const rpAudience = state.origin;
      const rpAssertion = await createAssertionFromPrimary(
        result.keypair.privateKey,
        result.certificate,
        rpAudience,
        expiresAt
      );

      storeLoggedInState(rpAudience, email);
      state.email = email;
      returnAssertion(rpAssertion);

    } catch (e) {
      if (e.needsAuth) {
        // Need to redirect to auth page
        redirectToPrimaryAuth(email, e.authUrl);
      } else {
        showError('Primary IdP provisioning failed: ' + e.message);
      }
    }
  }

  // Begin primary-IdP auth. We reach here after awaiting provisioning, so the
  // original sign-in tap is long gone — a window.open now is out-of-gesture and
  // mobile browsers block it. So: try to open once (desktop is lenient enough),
  // and if it's blocked, show a tap-to-continue screen whose button opens the
  // popup inside its own fresh gesture (which mobile allows).
  function redirectToPrimaryAuth(email, authUrl) {
    // Store state for return (used by popup when it loads dialog with #AUTH_RETURN)
    sessionStorage.setItem('browserid_pending_email', email);
    sessionStorage.setItem('browserid_pending_origin', state.origin);

    // Build auth URL
    const url = new URL(authUrl);
    url.searchParams.set('email', email);
    url.searchParams.set('return_to', window.location.origin + '/sign_in');
    const urlStr = url.toString();

    if (!openPrimaryAuthWindow(urlStr)) {
      // Blocked — defer to a user-initiated tap.
      state.pendingAuthUrl = urlStr;
      document.querySelectorAll('#primary-auth-continue-screen .idp-name')
        .forEach(el => { el.textContent = email.split('@')[1]; });
      showScreen('primaryAuthContinue');
    }
  }

  // Open the primary-IdP auth popup and wire the return listener. Returns false
  // (without touching the screen) if the browser blocked the popup, so the
  // caller can present a tap-to-continue affordance.
  function openPrimaryAuthWindow(urlStr) {
    // Open popup FIRST — if blocked, bail before changing screens.
    const popup = window.open(urlStr, 'browserid_auth', 'width=600,height=600');
    if (!popup) {
      return false;
    }

    // Show waiting screen
    showScreen('loading');
    const loadingText = document.querySelector('#loading p');
    if (loadingText) {
      loadingText.textContent = 'Authenticating with your email provider...';
    }

    // Set up auth return listener
    const AUTH_TIMEOUT = 120000; // 2 minutes
    let timeoutId = null;
    let pollId = null;

    function cleanup() {
      if (timeoutId) clearTimeout(timeoutId);
      if (pollId) clearInterval(pollId);
      window.removeEventListener('message', handleMessage);
    }

    function handleMessage(event) {
      // Accept messages from our own origin (popup loading dialog with #AUTH_RETURN)
      if (event.origin !== window.location.origin) return;

      if (event.data && event.data.type === 'browserid_auth_complete') {
        cleanup();
        if (event.data.success) {
          // Auth succeeded, continue provisioning
          handleAuthReturn();
        } else {
          showError('Authentication was cancelled.');
        }
      }
    }

    window.addEventListener('message', handleMessage);

    // Handle successful auth return from popup
    function handleAuthReturn() {
      // State was stored in sessionStorage before opening popup
      const email = sessionStorage.getItem('browserid_pending_email');
      const origin = sessionStorage.getItem('browserid_pending_origin');

      if (!email || !origin) {
        showError('Session expired. Please try again.');
        return;
      }

      // Restore state (don't clear yet - retryProvisioningAfterAuth uses it)
      state.email = email;
      state.origin = origin;

      // Update UI
      document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
      document.querySelectorAll('.rp-name').forEach(el => {
        el.textContent = new URL(origin).hostname;
      });

      // Clear stored state
      sessionStorage.removeItem('browserid_pending_email');
      sessionStorage.removeItem('browserid_pending_origin');

      // If this was an external-fallback login (apgv), retry provisioning at
      // that fallback (its /auth SMTP dance just set the email cookie), not the
      // primary retry (which would re-derive the IdP from the email domain).
      const fb = state.externalFallback || sessionStorage.getItem('browserid_pending_fallback');
      if (fb) {
        sessionStorage.removeItem('browserid_pending_fallback');
        state.externalFallback = fb;
        fallbackProvisionAndReturn(email, fb, false);
        return;
      }

      // Retry provisioning now that user is authenticated with IdP
      retryProvisioningAfterAuth(email);
    }

    // Timeout if auth takes too long
    timeoutId = setTimeout(() => {
      cleanup();
      if (popup && !popup.closed) {
        popup.close();
      }
      showError('Authentication timed out. Please try again.');
    }, AUTH_TIMEOUT);

    // Poll to detect if popup closed without responding
    pollId = setInterval(() => {
      if (popup.closed) {
        cleanup();
        showError('Authentication window was closed. Please try again.');
      }
    }, 500);

    return true;
  }

  // Create assertion from primary IdP certificate
  async function createAssertionFromPrimary(privateKey, certificate, audience, expiresAt) {
    const payload = { aud: audience, exp: expiresAt };
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
    const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '');
    const message = `${headerB64}.${payloadB64}`;

    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      privateKey,
      encoder.encode(message)
    );

    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return `${certificate}~${message}.${signatureB64}`;
  }

  // Complete sign-in and return assertion
  async function completeSignIn(email) {
    try {
      const audience = state.origin;
      const expiresAt = Date.now() + (5 * 60 * 1000); // 5 minutes

      const { certificate, privateKey, publicKey } = await generateCertificate(email);
      const assertion = await createAssertion(privateKey, certificate, audience, expiresAt);

      // Store in localStorage so communication_iframe knows we're logged in
      storeLoggedInState(audience, email);

      // Store keypair and certificate for silent assertions
      await storeEmailKeypair(email, publicKey, privateKey, certificate);

      state.email = email;
      returnAssertion(assertion);
    } catch (e) {
      showError('Failed to generate assertion: ' + e.message);
    }
  }

  // Single exit for every assertion-returning path. If the RP requested the SBO
  // typed-signing capability and this origin is not yet granted, show the
  // consent screen first; otherwise return immediately. Ordinary (assertion-
  // only) RPs are unaffected — the login contract is unchanged. Centralizing
  // here means the consent gate covers ALL paths (fresh cert, stored cert,
  // primary IdP), not just fresh sign-in.
  function returnAssertion(assertion) {
    if (state.sboSign && !sboSignGranted(state.origin)) {
      state.pendingAssertion = assertion;
      const emailEl = screens.sboConsent.querySelector('.email-display');
      if (emailEl) emailEl.textContent = state.email || '';
      showScreen('sboConsent');
      return;
    }
    showScreen('success');
    setTimeout(() => {
      sendResponse(buildAssertionResponse(assertion));
    }, 1000);
  }

  // The response returned to the RP. When the RP requested SBO signing, report
  // the grant decision explicitly so it never has to guess.
  // Show the "automatically sign in next time" checkbox only when the RP's
  // include.js signalled FedCM support+opt-in (so mingo's own dialog opens,
  // which don't set this, never show it). state.fedcmOptin tracks the choice.
  function maybeShowFedcmOptin(enabled) {
    // Record the flag; placeFedcmOptin (called from showScreen) moves the
    // checkbox into whichever sign-in screen becomes active. Also wire the
    // note that guides the user to the FedCM confirmation popup.
    //
    // Only on a fresh identity sign-in — NOT when the RP is provisioning a
    // specific identity (provision_email). That's a sub-step (e.g. mingo's
    // second dialog), where "auto sign-in next time" doesn't belong and would
    // fire a redundant FedCM chooser.
    state.fedcm = enabled && !state.provisionEmail;
    if (!state.fedcm) return;
    const box = document.getElementById('fedcm-optin');
    const note = document.getElementById('fedcm-optin-note');
    if (box && note) {
      const sync = () => { note.style.display = box.checked ? '' : 'none'; };
      box.addEventListener('change', sync);
      sync();
    }
  }

  function buildAssertionResponse(assertion) {
    const resp = { assertion };
    if (state.sboSign) {
      resp.sbo_sign_granted = sboSignGranted(state.origin);
    }
    // When the RP requested a specific identity (provision_email), return it so
    // the RP knows exactly who was provisioned/signed in.
    if (state.provisionEmail) resp.email = state.email;
    // FedCM opt-in: only if the checkbox was shown (state.fedcm) AND the user
    // actively ticked it. Read at response time so it reflects the real choice
    // on whatever screen they finished on (default is UNCHECKED — explicit opt-in).
    const optin = document.getElementById('fedcm-optin');
    if (state.fedcm && optin && optin.checked) resp.fedcm_optin = true;
    return resp;
  }

  // Per-origin grant for the SBO typed-signing capability, persisted in the same
  // `siteInfo` localStorage map communication_iframe reads via storage.site.get.
  function sboSignGranted(origin) {
    try {
      const siteInfo = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      return !!(siteInfo[origin] && siteInfo[origin].sbo_sign_granted);
    } catch (e) {
      return false;
    }
  }

  function grantSboSign(origin) {
    try {
      const siteInfo = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      siteInfo[origin] = siteInfo[origin] || {};
      siteInfo[origin].sbo_sign_granted = true;
      localStorage.setItem('siteInfo', JSON.stringify(siteInfo));
    } catch (e) {
      console.warn('Failed to store SBO signing grant:', e);
    }
  }

  // Communication with parent window
  function sendResponse(data) {
    // WinChan callback takes precedence
    if (state.winchanCallback) {
      state.winchanCallback(data);
      state.winchanCallback = null;
      return;
    }
    // Fallback to postMessage for simple popup case
    if (window.opener) {
      window.opener.postMessage(data, state.origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(data, state.origin);
    } else if (state.callback) {
      state.callback(data);
    }
  }

  function sendCancel() {
    if (state.winchanCallback) {
      state.winchanCallback(null);
      state.winchanCallback = null;
    } else {
      sendResponse({ assertion: null, cancelled: true });
    }
  }

  // Event handlers
  function setupEventHandlers() {
    // Email form
    document.getElementById('email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();

      if (!email) {
        document.getElementById('email-error').textContent = 'Email is required';
        return;
      }

      state.email = email;
      document.querySelectorAll('.email-display').forEach(el => el.textContent = email);

      showScreen('loading');

      try {
        // Subordinate substitution for a TYPED identity (mingo-cm8z), same as the
        // chooser path: typing a subordinate to log into its own issuer
        // authenticates the parent instead. No-ops when not applicable / signed out.
        const parent = await maybeSubstituteParent(email);
        if (parent) return await handleEmailChosen(parent, true);

        const addressInfo = await checkEmail(email);

        // Handle based on type and state
        if (addressInfo.type === 'primary' && addressInfo.prov) {
          // Primary IdP flow
          if (addressInfo.state === 'transition_to_secondary') {
            // Was primary, now secondary with password
            showScreen('password');
          } else if (addressInfo.state === 'transition_no_password') {
            // Was primary, now secondary without password - need to set one
            await handleNoPasswordTransition(email);
          } else {
            // Normal primary flow (known or unknown)
            await handlePrimaryIdP(email, addressInfo);
          }
        } else {
          // Secondary flow — also covers a primary email transiently seen as secondary
          // (e.g. a discovery hiccup), whose existing record yields a transition_* state.
          // Mirror handleEmailChosen so an *existing* account never falls into create.
          //
          // Fail fast if the RP didn't accept this broker as a fallback IdP
          // (spec §8.1). transition_to_primary is exempt — it routes to a
          // primary, not the broker.
          if (addressInfo.state !== 'transition_to_primary' && !brokerFallbackAccepted()) {
            const fb = firstExternalAcceptedFallback();
            if (fb) return await handleExternalFallback(email, fb);
            const dom = state.brokerDomain || location.hostname;
            showError('This site doesn’t accept email sign-in via ' + dom +
              '. Use an email whose domain is its own identity provider.');
            return;
          }
          if (addressInfo.state === 'known') {
            showScreen('password');
          } else if (addressInfo.state === 'transition_to_secondary') {
            // Existing account (was primary) — authenticate with password
            showScreen('password');
          } else if (addressInfo.state === 'transition_no_password') {
            // Existing account without a password — prove control, set one
            await handleNoPasswordTransition(email);
          } else if (addressInfo.state === 'transition_to_primary' && addressInfo.prov) {
            // Was secondary, now primary - show transition info screen
            const domain = email.split('@')[1];
            document.querySelectorAll('.idp-name').forEach(el => el.textContent = domain);
            state.pendingAddressInfo = addressInfo;
            showScreen('primaryTransition');
          } else if (addressInfo.state === 'unknown') {
            // Genuinely new email — create an account
            showScreen('create');
          } else {
            showError('Cannot sign in with this email (unexpected state: ' + addressInfo.state + ')');
          }
        }
      } catch (e) {
        showError('Failed to check email: ' + e.message);
      }
    });

    // Password form (sign in)
    document.getElementById('password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;

      if (!password) {
        document.getElementById('password-error').textContent = 'Password is required';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.authenticate, 'POST', {
          email: state.email,
          pass: password,
          ephemeral: false
        });

        await completeSignIn(state.email);
      } catch (e) {
        showScreen('password');
        document.getElementById('password-error').textContent = e.message;
      }
    });

    // Create account form
    document.getElementById('create-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('create-password').value;
      const confirmPassword = document.getElementById('confirm-password').value;

      if (password.length < 8) {
        document.getElementById('create-password-error').textContent = 'Password must be at least 8 characters';
        return;
      }

      if (password !== confirmPassword) {
        document.getElementById('confirm-password-error').textContent = 'Passwords do not match';
        return;
      }

      state.password = password;
      showScreen('loading');

      try {
        await apiCall(API.stageUser, 'POST', {
          email: state.email,
          pass: password
        });

        showScreen('verify');
      } catch (e) {
        // The account already exists (e.g. we reached 'create' from a transient
        // mis-detection). Don't dead-end — route to sign-in for the existing account.
        if (/already exists/i.test(e.message)) {
          document.querySelectorAll('.email-display').forEach(el => el.textContent = state.email);
          showScreen('password');
          const pwErr = document.getElementById('password-error');
          if (pwErr) pwErr.textContent = 'This email is already registered — sign in below.';
        } else {
          showScreen('create');
          document.getElementById('create-password-error').textContent = e.message;
        }
      }
    });

    // Verification form
    document.getElementById('verify-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('verification-code').value.trim();

      if (!code || code.length !== 6) {
        document.getElementById('verify-error').textContent = 'Please enter the 6-digit code';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.completeUserCreation, 'POST', { token: code });
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('verify');
        document.getElementById('verify-error').textContent = e.message;
      }
    });

    // Forgot password link
    document.getElementById('forgot-password-link').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('reset-email').value = state.email || '';
      showScreen('resetEmail');
    });

    // Reset email form
    document.getElementById('reset-email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('reset-email').value.trim();

      if (!email) {
        document.getElementById('reset-email-error').textContent = 'Email is required';
        return;
      }

      state.email = email;
      showScreen('loading');

      try {
        await apiCall(API.stageReset, 'POST', { email });
        showScreen('resetPassword');
      } catch (e) {
        showScreen('resetEmail');
        document.getElementById('reset-email-error').textContent = e.message;
      }
    });

    // Reset password form
    document.getElementById('reset-password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('reset-code').value.trim();
      const password = document.getElementById('new-password').value;

      if (!code || code.length !== 6) {
        document.getElementById('reset-code-error').textContent = 'Please enter the 6-digit code';
        return;
      }

      if (password.length < 8) {
        document.getElementById('new-password-error').textContent = 'Password must be at least 8 characters';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.completeReset, 'POST', { token: code, pass: password });
        // Now sign in with the new password
        await apiCall(API.authenticate, 'POST', {
          email: state.email,
          pass: password,
          ephemeral: false
        });
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('resetPassword');
        if (e.message.includes('code')) {
          document.getElementById('reset-code-error').textContent = e.message;
        } else {
          document.getElementById('new-password-error').textContent = e.message;
        }
      }
    });

    // Pick email form
    document.getElementById('pick-email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const selected = document.querySelector('input[name="selected-email"]:checked');

      if (!selected) {
        return;
      }

      state.email = selected.value;
      await handleEmailChosen(state.email);
    });

    // Add email link - go to add email screen (not login screen)
    document.getElementById('add-email-link').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('new-email').value = '';
      document.getElementById('add-email-error').textContent = '';
      showScreen('addEmail');
    });

    // Add email form
    document.getElementById('add-email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('new-email').value.trim();

      if (!email) {
        document.getElementById('add-email-error').textContent = 'Email is required';
        return;
      }

      state.newEmail = email;
      document.querySelectorAll('.new-email-display').forEach(el => el.textContent = email);

      showScreen('loading');

      try {
        // A primary-IdP email must be proven via its own IdP (provisioning), not
        // SMTP. Detect it first — otherwise a primary like alice@example.com (whose
        // domain runs BrowserID) wrongly gets an emailed code. Only genuine
        // secondary emails fall through to SMTP staging. handlePrimaryIdP provisions
        // against the IdP and, when a session exists, links the email into the
        // current account (see auth_with_assertion linking, mingo-1c6v).
        const addressInfo = await checkEmail(email);
        if (addressInfo.type === 'primary' && addressInfo.prov) {
          state.email = email;
          document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
          await handlePrimaryIdP(email, addressInfo);
          return;
        }

        await apiCall(API.stageEmail, 'POST', { email });
        showScreen('addEmailVerify');
      } catch (e) {
        showScreen('addEmail');
        document.getElementById('add-email-error').textContent = e.message;
      }
    });

    // Add email verification form
    document.getElementById('add-email-verify-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('add-email-code').value.trim();

      if (!code || code.length !== 6) {
        document.getElementById('add-email-verify-error').textContent = 'Please enter the 6-digit code';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.completeEmailAddition, 'POST', { token: code });
        // Email added successfully - use it to sign in
        state.email = state.newEmail;
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('addEmailVerify');
        document.getElementById('add-email-verify-error').textContent = e.message;
      }
    });

    // Set password form (for primary->secondary transition without password)
    document.getElementById('set-password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('set-password').value;
      const confirm = document.getElementById('set-password-confirm').value;

      // Clear previous errors
      document.getElementById('set-password-error').textContent = '';
      document.getElementById('set-password-confirm-error').textContent = '';

      if (password.length < 8) {
        document.getElementById('set-password-error').textContent = 'Password must be at least 8 characters';
        return;
      }

      if (password !== confirm) {
        document.getElementById('set-password-confirm-error').textContent = 'Passwords do not match';
        return;
      }

      showScreen('loading');

      try {
        await apiCall('/wsapi/set_password', 'POST', {
          email: state.email,
          pass: password
        });

        await apiCall(API.authenticate, 'POST', {
          email: state.email,
          pass: password,
          ephemeral: false
        });

        await completeSignIn(state.email);
      } catch (e) {
        showScreen('setPassword');
        document.getElementById('set-password-error').textContent = e.message;
      }
    });

    // Continue to primary IdP button (for secondary->primary transition)
    document.getElementById('continue-to-primary').addEventListener('click', async () => {
      showScreen('loading');

      try {
        const addressInfo = await fetch(`${API.addressInfo}?email=${encodeURIComponent(state.email)}`)
          .then(r => r.json());

        if (addressInfo.type === 'primary' && addressInfo.prov) {
          await handlePrimaryIdP(state.email, addressInfo);
        } else {
          showError('This email is no longer a primary IdP');
        }
      } catch (e) {
        showError('Failed to connect to email provider: ' + e.message);
      }
    });

    // Tap-to-continue: open the primary-IdP auth popup from a real user gesture
    // (used when the earlier auto-open was blocked, e.g. on mobile).
    document.getElementById('continue-primary-auth').addEventListener('click', () => {
      if (state.pendingAuthUrl && !openPrimaryAuthWindow(state.pendingAuthUrl)) {
        showError('Could not open the sign-in window. Please allow popups for this site and try again.');
      }
    });

    // Back to pick email buttons
    document.querySelectorAll('.back-to-pick').forEach(btn => {
      btn.addEventListener('click', async () => {
        // Refresh email list and go back to pick screen
        try {
          const emailsResponse = await apiCall(API.listEmails);
          state.emails = emailsResponse.emails || [];
          state.derived = derivedMapFromResponse(emailsResponse);
          populateEmailList(state.emails);
        } catch (e) {
          // Keep existing list
        }
        showScreen('pickEmail');
      });
    });

    // Back buttons
    document.querySelectorAll('.back').forEach(btn => {
      btn.addEventListener('click', () => {
        showScreen('email');
      });
    });

    // Cancel buttons
    document.querySelectorAll('.cancel').forEach(btn => {
      btn.addEventListener('click', () => {
        sendCancel();
      });
    });

    // Try again button
    document.querySelector('.try-again').addEventListener('click', () => {
      showScreen('email');
    });

    // SBO signing consent: Allow grants this origin the typed-signing
    // capability; Not now returns the assertion without granting (login still
    // succeeds; the iframe will report not_granted until granted later).
    function finishAfterConsent() {
      const assertion = state.pendingAssertion;
      state.pendingAssertion = null;
      showScreen('success');
      setTimeout(() => {
        sendResponse(buildAssertionResponse(assertion));
      }, 1000);
    }
    document.getElementById('sbo-consent-allow').addEventListener('click', () => {
      grantSboSign(state.origin);
      finishAfterConsent();
    });
    document.getElementById('sbo-consent-deny').addEventListener('click', () => {
      finishAfterConsent();
    });

    // Handle messages from parent
    window.addEventListener('message', (e) => {
      if (e.data && e.data.type === 'browserid:request') {
        state.origin = e.origin;
        state.sboSign = !!(e.data.params && e.data.params.sboSign);
        state.provisionEmail = (e.data.params && e.data.params.provisionEmail) || null;
        state.acceptedFallbacks = normalizeAcceptedFallbacks(e.data.params && e.data.params.acceptedFallbacks);
        document.querySelectorAll('.rp-name').forEach(el => {
          el.textContent = new URL(e.origin).hostname;
        });
        init();
      }
    });
  }

  // Build the subordinate -> parent map from a list_emails response (mingo-cm8z).
  function derivedMapFromResponse(resp) {
    const map = {};
    (resp && resp.derived || []).forEach(d => { map[d.email] = d.parent_email; });
    return map;
  }

  // Escape a value for safe interpolation into innerHTML.
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  // Populate email list. Derived/subordinate identities (mingo-cm8z) get a
  // distinct sub-label naming the parent they sign in through.
  function populateEmailList(emails) {
    const list = document.getElementById('email-list');
    list.innerHTML = '';

    emails.forEach((emailStr, index) => {
      const parent = state.derived[emailStr];
      const li = document.createElement('li');
      if (parent) li.className = 'derived';
      const safeEmail = escapeHtml(emailStr);
      const sub = parent
        ? `<span class="email-sub">signs in via ${escapeHtml(parent)}</span>`
        : '';
      li.innerHTML = `
        <label>
          <input type="radio" name="selected-email" value="${safeEmail}" ${index === 0 ? 'checked' : ''}>
          <span class="email-text">${safeEmail}${sub}</span>
        </label>
      `;
      list.appendChild(li);
    });
  }

  // Initialize
  async function init() {
    // Migrate any legacy localStorage keys into non-extractable IndexedDB (e2fi).
    try { await Keystore.migrateFromLocalStorage(); } catch (e) { console.warn('keystore migrate:', e); }
    // Learn this broker's own issuer domain (its fallback-IdP identity) so the
    // acceptedFallbacks gate (spec §8.1) works on every entry path, including
    // the provisionEmail fast-path below.
    try { state.brokerDomain = (await apiCall(API.sessionContext)).domain || state.brokerDomain; } catch {}

    // If the RP asked to provision/sign in a SPECIFIC identity, skip the chooser
    // entirely and drive that identity straight through (primary provisioning for
    // a primary email, normal sign-in otherwise).
    if (state.provisionEmail) {
      showScreen('loading');
      handleEmailChosen(state.provisionEmail);
      return;
    }
    try {
      // Check if already authenticated
      const session = await apiCall(API.sessionContext);

      if (session.authenticated) {
        // Get user's emails
        const emailsResponse = await apiCall(API.listEmails);
        state.emails = emailsResponse.emails || [];
        state.derived = derivedMapFromResponse(emailsResponse);

        if (state.emails.length >= 1) {
          // Show email picker - even with one email, let user confirm or add another
          populateEmailList(state.emails);
          showScreen('pickEmail');
        } else {
          // No emails (shouldn't happen), show email entry
          showScreen('email');
        }
      } else {
        // Not authenticated, show email entry
        showScreen('email');
      }
    } catch (e) {
      showScreen('email');
    }
  }

  // Check for auth return from primary IdP
  function checkAuthReturn() {
    const hash = window.location.hash;

    if (hash === '#AUTH_RETURN' || hash === '#AUTH_RETURN_CANCEL') {
      const success = hash === '#AUTH_RETURN';

      // If we're in a popup, notify the opener and close
      if (window.opener && window.opener !== window) {
        try {
          window.opener.postMessage({
            type: 'browserid_auth_complete',
            success: success
          }, window.location.origin);
          window.close();
          return true;
        } catch (e) {
          // Opener may have been closed, fall through to standalone handling
          console.warn('Failed to notify opener:', e);
        }
      }

      // Clear hash from URL
      history.replaceState(null, '', window.location.pathname + window.location.search);

      // Restore state from sessionStorage
      const email = sessionStorage.getItem('browserid_pending_email');
      const origin = sessionStorage.getItem('browserid_pending_origin');

      if (!email || !origin) {
        console.error('Missing auth return state');
        showScreen('email');
        return true;
      }

      state.email = email;
      state.origin = origin;

      // Clear stored state
      sessionStorage.removeItem('browserid_pending_email');
      sessionStorage.removeItem('browserid_pending_origin');

      // Update UI
      document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
      document.querySelectorAll('.rp-name').forEach(el => {
        el.textContent = new URL(origin).hostname;
      });

      if (success) {
        // Auth succeeded - retry provisioning
        retryProvisioningAfterAuth(email);
      } else {
        // Auth was cancelled
        showError('Authentication was cancelled');
      }

      return true;  // Signal that auth return was handled
    }

    return false;  // No auth return, proceed with normal init
  }

  // Retry provisioning after user authenticated with primary IdP
  async function retryProvisioningAfterAuth(email) {
    showScreen('loading');

    try {
      // Get address info again to get provisioning URL
      const addressInfo = await checkEmail(email);

      if (addressInfo.type !== 'primary' || !addressInfo.prov) {
        throw new Error('Email is no longer a primary IdP');
      }

      // Retry provisioning (should succeed now that user is authenticated with IdP)
      const result = await tryPrimaryProvisioning(email, addressInfo.prov, addressInfo.auth);

      const expiresAt = Date.now() + (5 * 60 * 1000);

      // First assertion: audience = broker (to prove email ownership to browserid)
      const brokerAudience = window.location.origin;
      const brokerAssertion = await createAssertionFromPrimary(
        result.keypair.privateKey,
        result.certificate,
        brokerAudience,
        expiresAt
      );

      // Authenticate with broker to establish session
      await apiCall('/wsapi/auth_with_assertion', 'POST', {
        assertion: brokerAssertion,
        ephemeral: false
      });

      // Store keypair for future use
      await storeEmailKeypair(
        email,
        result.keypair.publicKey,
        result.keypair.privateKey,
        result.certificate
      );

      // Record a derived/subordinate identity's parent (mingo-cm8z). The IdP
      // supplied `subordinate_to` privately over the provisioning channel (never
      // in the cert). Both this email and the parent are now in the account (the
      // auth_with_assertion above linked this one), so set_parent will accept it.
      // Non-fatal: a failure just means the substitution UX won't kick in yet.
      if (result.metadata && result.metadata.subordinate_to) {
        try {
          await apiCall('/wsapi/set_parent', 'POST', {
            email: email,
            parent_email: result.metadata.subordinate_to
          });
        } catch (e) {
          console.warn('set_parent failed (non-fatal):', e.message);
        }
      }

      // Second assertion: audience = RP (to return to relying party)
      const rpAudience = state.origin;
      const rpAssertion = await createAssertionFromPrimary(
        result.keypair.privateKey,
        result.certificate,
        rpAudience,
        expiresAt
      );

      storeLoggedInState(rpAudience, email);
      state.email = email;
      returnAssertion(rpAssertion);

    } catch (e) {
      if (e.needsAuth) {
        // Still needs auth? Something went wrong
        showError('Authentication failed. Please try again.');
      } else {
        showError('Provisioning failed after authentication: ' + (e.message || e));
      }
    }
  }

  // Setup and start
  setupEventHandlers();

  // Check for auth return from primary IdP before normal init
  if (!checkAuthReturn()) {
    // Normal initialization
    const params = new URLSearchParams(window.location.search);
    const origin = params.get('origin');

    if (origin) {
      state.origin = origin;
      state.sboSign = params.get('sbo_sign') === '1';
      state.provisionEmail = params.get('provision_email');
      state.acceptedFallbacks = normalizeAcceptedFallbacks(
        params.get('accepted_fallbacks') ? params.get('accepted_fallbacks').split(',') : null);
      document.querySelectorAll('.rp-name').forEach(el => {
        el.textContent = new URL(origin).hostname;
      });
      init();
    }

    // Also support WinChan protocol for include.js compatibility
    if (typeof WinChan !== 'undefined' && WinChan.onOpen) {
      try {
        // Store the handle so we can call detach() before navigating to IdP auth
        state.winchanHandle = WinChan.onOpen(function(origin, args, cb) {
          if (args && args.params) {
            state.origin = origin;
            state.sboSign = !!args.params.sboSign;
            state.provisionEmail = args.params.provisionEmail || null;
            state.acceptedFallbacks = normalizeAcceptedFallbacks(args.params.acceptedFallbacks);
            state.winchanCallback = cb;
            // FedCM opt-in: include.js sets this when the browser supports FedCM
            // and the RP opted in. Show the "auto sign-in next time" checkbox.
            maybeShowFedcmOptin(!!args.params.fedcm);
            document.querySelectorAll('.rp-name').forEach(el => {
              el.textContent = new URL(origin).hostname;
            });
            init();
          }
        });
      } catch (e) {
        // WinChan.onOpen may throw if not in popup context
        console.log('WinChan not available:', e.message);
      }
    }
  }
})();
