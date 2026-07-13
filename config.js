// Marketing-site configuration.
//
// This static site (www.browserid.me) is a SEPARATE ORIGIN from the auth/issuer
// broker (browserid.me). It holds no keys, cookies, or wsapi — only public
// content — so it is the safe place for analytics. Everything that needs the
// broker (the guestbook feed, the "Sign in" link) is addressed at `authOrigin`,
// cross-origin.
//
// Deploy sets `authOrigin` to the production broker. Locally / in tests, serve a
// config.js that points at your running broker instead (the e2e harness does).
window.BROWSERID = {
  authOrigin: "https://browserid.me",
};
