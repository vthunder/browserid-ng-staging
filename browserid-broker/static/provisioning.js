/*
 * BrowserID Provisioning Module
 * Handles hidden iframe communication with primary IdP provisioning pages
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

(function(global) {
  'use strict';

  const Provisioning = {
    _iframe: null,
    _iframeOrigin: null,
    _pendingCallbacks: {},
    _callId: 0,
    _onSuccess: null,
    _onFailure: null,
    _email: null,
    _keypair: null,
    _timeout: null,

    /**
     * Attempt to provision a certificate from a primary IdP
     * @param {string} provisioningUrl - The IdP's provisioning endpoint
     * @param {string} email - The email to provision
     * @param {function} onSuccess - Called with {certificate, keypair} on success
     * @param {function} onFailure - Called with reason on failure
     */
    start: function(provisioningUrl, email, onSuccess, onFailure) {
      // Clean up any previous provisioning attempt first
      this._cleanup();

      this._onSuccess = onSuccess;
      this._onFailure = onFailure;
      this._email = email;

      // Determine origin from URL
      const url = new URL(provisioningUrl);
      this._iframeOrigin = url.origin;

      // Create hidden iframe
      this._iframe = document.createElement('iframe');
      this._iframe.style.display = 'none';
      this._iframe.src = provisioningUrl;
      document.body.appendChild(this._iframe);

      // Set timeout for provisioning
      this._timeout = setTimeout(() => {
        this._cleanup();
        onFailure('Provisioning timeout');
      }, 30000); // 30 second timeout
    },

    /**
     * Handle messages from provisioning iframe
     */
    handleMessage: function(event) {
      if (!this._iframe || event.source !== this._iframe.contentWindow) {
        return;
      }

      if (event.origin !== this._iframeOrigin) {
        return;
      }

      const data = event.data;
      if (!data || data.type !== 'browserid:provisioning') {
        return;
      }

      // SPIKE C — where the cert-issuance step is replaced.
      //
      // Today the iframe drives THREE postMessage round-trips: beginProvisioning
      // (auth handshake), genKeyPair (browser makes a key, hands the IdP page the
      // pubkey), registerCertificate (IdP page relays back the minted cert).
      //
      // Direction C KEEPS beginProvisioning (the interactive auth ceremony) but
      // DELETES the genKeyPair + registerCertificate hops: once auth succeeds the
      // broker generates the key itself (_generateKeyPair, already here) and gets
      // the cert by POSTing the "Login" shape to the IdP's /provision/mint over
      // HTTP — i.e. `httpMintAfterAuth()` below replaces `case 'genKeyPair'` /
      // `case 'registerCertificate'`.
      //
      // BLOCKER (honest): /provision/mint's login self-mint is SESSION-authed,
      // and the credentialed fetch to a *third-party* primary IdP is a
      // cross-site cookie'd request — exactly the ITP surface the iframe already
      // dies on. So this HTTP-mint replacement is only actually reachable when
      // the mint target is THIS broker (the fallback/secondary path in
      // dialog.js::generateCertificate, which this spike wires up for real). For
      // a genuine third-party primary the mint would need a delegation-chain
      // bundle instead of a session — see SPIKE-C-REPORT.md.
      switch (data.method) {
        case 'beginProvisioning':
          // Respond with email and duration
          this._respond(data.id, {
            email: this._email,
            cert_duration_s: 24 * 60 * 60  // 24 hours
          });
          break;

        case 'genKeyPair':
          // Generate keypair and return public key
          this._generateKeyPair().then(keypair => {
            this._keypair = keypair;
            this._respond(data.id, { publicKey: keypair.publicKeyJson });
          }).catch(err => {
            this._fail('Key generation failed: ' + err.message);
          });
          break;

        case 'registerCertificate':
          // Success! Store certificate and notify. `metadata` is optional private
          // provisioning metadata from the IdP (e.g. { subordinate_to }) carried
          // over this channel only — never in the cert (mingo-cm8z).
          clearTimeout(this._timeout);
          const cert = data.data.certificate;
          if (this._onSuccess) {
            this._onSuccess({
              certificate: cert,
              keypair: this._keypair,
              metadata: (data.data && data.data.metadata) || null
            });
          }
          this._cleanup();
          break;

        case 'raiseProvisioningFailure':
          // Provisioning failed
          clearTimeout(this._timeout);
          if (this._onFailure) {
            this._onFailure(data.data.reason || 'Provisioning failed');
          }
          this._cleanup();
          break;
      }
    },

    /**
     * Send response back to iframe
     */
    _respond: function(id, result) {
      if (this._iframe && this._iframe.contentWindow) {
        this._iframe.contentWindow.postMessage({
          type: 'browserid:provisioning:response',
          id: id,
          result: result
        }, this._iframeOrigin);
      }
    },

    /**
     * Generate Ed25519 keypair
     */
    _generateKeyPair: async function() {
      // Non-extractable private key (e2fi): JS never sees the raw bytes.
      const keyPair = await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        false,
        ['sign', 'verify']
      );

      const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        publicKeyJson: JSON.stringify({
          algorithm: 'Ed25519',
          publicKey: publicKeyJwk.x
        }),
        publicKeyJwk: publicKeyJwk
      };
    },

    /**
     * SPIKE C: mint the login cert over HTTP through the agent endpoint,
     * replacing the genKeyPair + registerCertificate postMessage hops. Called
     * once beginProvisioning has established the auth session. `mintOrigin` is
     * the IdP base (same-origin broker in the demonstrable path). Returns
     * { certificate, keypair } — the same shape the postMessage flow yielded.
     */
    httpMintAfterAuth: async function(mintOrigin, email) {
      const keypair = await this._generateKeyPair();
      const resp = await fetch(mintOrigin + '/provision/mint', {
        method: 'POST',
        credentials: 'include',            // the auth-ceremony session cookie
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email,
          pubkey: JSON.parse(keypair.publicKeyJson),
          ephemeral: false
          // csrf omitted here for brevity; dialog.js::apiCall injects it.
        })
      });
      const data = await resp.json();
      if (!resp.ok || !data.success) {
        throw new Error(data.reason || 'mint failed');
      }
      return { certificate: data.cert, keypair: keypair };
    },

    /**
     * Clean up iframe and state
     */
    _cleanup: function() {
      if (this._iframe) {
        this._iframe.remove();
        this._iframe = null;
      }
      this._iframeOrigin = null;
      this._keypair = null;
      this._email = null;
      if (this._timeout) {
        clearTimeout(this._timeout);
        this._timeout = null;
      }
    },

    _fail: function(reason) {
      clearTimeout(this._timeout);
      if (this._onFailure) {
        this._onFailure(reason);
      }
      this._cleanup();
    }
  };

  // Listen for messages
  window.addEventListener('message', function(event) {
    Provisioning.handleMessage(event);
  });

  global.BrowserID = global.BrowserID || {};
  global.BrowserID.Provisioning = Provisioning;

})(window);
