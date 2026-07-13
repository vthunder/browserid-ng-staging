# Static marketing site (www.browserid.me) — a separate origin from the broker.
# Tiny nginx image; no build step. Deployed as its own Dokku app so it shares
# no origin (keystore/cookies/wsapi) with the auth/issuer broker.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html guestbook.html config.js /usr/share/nginx/html/

EXPOSE 80
