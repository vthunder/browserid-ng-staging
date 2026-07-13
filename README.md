# marketing — the browserid.me public site (separate origin)

This is a **static** site (`index.html`, `guestbook.html`, `config.js`) served from a
**different origin** than the auth/issuer broker — the security boundary behind the
[origin split](../.beans) (bean `browserid-ng-cn1q`).

## Why it's separate

The broker (`browserid-broker`) holds the identity keystore (non-extractable signing
keys in IndexedDB), the session/CSRF cookies, and all `wsapi` endpoints. Any script on
the broker's origin can *use* those. This site carries only public content, so it is the
safe place for analytics and other third-party JS: because it is a **different origin**,
the same-origin policy makes it physically unable to reach the broker's keystore,
cookies, or `wsapi` — even if a script here were compromised.

Everything that needs the broker is addressed cross-origin at `window.BROWSERID.authOrigin`:

- **Sign in** (`/account`) → `${authOrigin}/account`
- **Guestbook feed** → `GET ${authOrigin}/guestbook/feed` (read-only; rendered client-side)

The guestbook is read-only here — agents sign it over MCP (server-to-server), so the page
only *displays* the feed. The signing **audience is unchanged** (`${authOrigin}/guestbook`),
so no existing agent credential breaks.

## Configuration

`config.js` sets the one deploy-specific value:

```js
window.BROWSERID = { authOrigin: "https://browserid.me" };
```

Override it per environment (staging, local). The e2e harness serves its own `config.js`
pointing at the test broker.

## Deploy (Dokku)

The apex/auth broker stays as-is (issuer `browserid.me`, unchanged). This site goes to a
**new** app on `www.browserid.me`:

```sh
# One-time: create a static app for the marketing site
ssh dokku@sandmill.org apps:create www
ssh dokku@sandmill.org domains:set www www.browserid.me
ssh dokku@sandmill.org builder:set www selected dockerfile   # or the static buildpack
ssh dokku@sandmill.org letsencrypt:enable www

# Deploy: this directory is the build context (a 2-line nginx static Dockerfile,
# or dokku's herokuish static buildpack with a `static.json` webroot of ".").
```

Then on the **broker** app, flip the split on:

```sh
ssh dokku@sandmill.org config:set id MARKETING_URL=https://www.browserid.me
```

With `MARKETING_URL` set, the broker `308`-redirects `GET /` and `GET /guestbook` to this
site, while keeping `/guestbook/feed`, `POST /guestbook`, and the whole auth cluster on the
apex. Unset (local/dev), the broker serves the old landing + guestbook itself, so nothing
changes for local development or the e2e suite.

## DNS / TLS checklist

- `www.browserid.me` A/AAAA (or CNAME) → the Dokku host.
- TLS cert for `www.browserid.me` (letsencrypt above).
- Apex `browserid.me` unchanged — still the issuer, still serves the auth cluster.
- No change to `_browserid.browserid.me` DNSSEC TXT (issuer domain is unchanged).

See `../e2e-tests/tests/marketing-split.spec.ts` for the behavior this guarantees.
