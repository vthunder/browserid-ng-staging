// PostHog analytics — MARKETING ORIGIN ONLY (www.browserid.me).
//
// This origin holds no keystore, cookies, or wsapi (that's the whole point of
// the origin split), so analytics JS here cannot reach anything sensitive. We
// still lock PostHog down hard, defense-in-depth:
//   - self-hosted, pinned bundle (vendor/posthog.js) — no third-party CDN JS;
//   - ingestion reverse-proxied through /ingest on this origin — no third-party
//     connection, and ad-blockers don't eat the data;
//   - autocapture / session recording / surveys OFF — nothing scrapes the DOM;
//   - remote-config (`/flags`) channel OFF — a compromised PostHog account can't
//     push behavior or inject site apps;
//   - no external dependency loading — only the pinned bundle ever runs;
//   - localStorage persistence (no cookies), identified_only person profiles.
//
// The auth origin (browserid.me) runs NO analytics JS — its funnel is captured
// server-side from the broker. See browserid-broker/src/analytics.rs.
(function () {
  if (typeof window.posthog === "undefined" || !window.posthog.init) return;

  window.posthog.init("phc_xmNHkmogEcdcDpVTeqYkyccBaZt2AWushSA3i5RctMAp", {
    api_host: "/ingest", // reverse-proxied to us.i.posthog.com by nginx
    ui_host: "https://us.posthog.com",

    // Website analytics we DO want.
    capture_pageview: true,
    capture_pageleave: true,

    // Everything that could scrape the page or be remotely weaponized: OFF.
    autocapture: false,
    disable_session_recording: true,
    disable_surveys: true,
    advanced_disable_flags: true, // closes the /flags remote-config + site-app channel
    disable_external_dependency_loading: true, // only the pinned bundle runs

    // Privacy posture for an auth product's marketing site.
    persistence: "localStorage", // no cookies at all
    cross_subdomain_cookie: false, // never scope a cookie to .browserid.me
    person_profiles: "identified_only",

    // Belt-and-suspenders: drop anything that looks like an email or an OTP,
    // in case a future event property ever carries one.
    before_send: function (event) {
      if (!event || !event.properties) return event;
      var EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
      var OTP = /\b\d{6}\b/;
      Object.keys(event.properties).forEach(function (k) {
        var v = event.properties[k];
        if (typeof v === "string" && (EMAIL.test(v) || OTP.test(v))) {
          event.properties[k] = "[redacted]";
        }
      });
      return event;
    },
  });

  // Lightweight, explicit funnel signals (no autocapture). Capture intent on the
  // key marketing CTAs so we can see landing → guestbook drop-off.
  function on(sel, handler) {
    document.querySelectorAll(sel).forEach(function (el) {
      el.addEventListener("click", handler);
    });
  }
  function text(el) {
    return (el.textContent || "").trim().slice(0, 60);
  }

  on(".aud-toggle button", function () {
    window.posthog.capture("audience_toggle", { audience: this.dataset.aud });
  });
  on(".hero-actions .btn", function () {
    window.posthog.capture("hero_cta_click", { label: text(this), href: this.getAttribute("href") });
  });
  on('a[href="/guestbook"], a[href$="/guestbook"]', function () {
    window.posthog.capture("guestbook_link_click", { from: location.pathname });
  });
  on(".try summary", function () {
    window.posthog.capture("guestbook_setup_expand");
  });
})();
