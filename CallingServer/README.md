# Self-hosted call service

This folder is the server-side foundation for native LiveKit calling. The token
API creates unguessable invitations and issues short-lived participant tokens;
the LiveKit API key and secret stay on the server. Room joins are limited to
eight participants. The service is not live until an Ubuntu VPS, DNS, TLS
certificates, firewall rules, and app clients have been configured.

## Required VPS setup

Use Ubuntu with Docker Compose and a public IPv4 address. Configure DNS:

- `calls.example.com` -> VPS public address
- `api.calls.example.com` -> VPS public address
- `turn.example.com` -> VPS public address

Replace `example.com` in `livekit.yaml` and `Caddyfile`. Obtain a trusted TLS
certificate for the TURN name at
`/etc/letsencrypt/live/turn.example.com/`. Caddy obtains/renews certificates
for the HTTPS and WebSocket hostnames automatically once DNS points to the VPS.

Copy `.env.example` to `.env`, generate a random API key and secret, and use
exactly the same pair in `LIVEKIT_API_KEY` / `LIVEKIT_API_SECRET` and under
`keys:` in `livekit.yaml`. Set `CALL_ALLOWED_ORIGINS` to the exact app web
origin(s); do not use `*`. Keep `.env`, certificates, and `livekit.yaml` private.

The firewall must allow:

- TCP `80, 443` for Caddy and certificate issuance
- TCP `7881` for LiveKit ICE/TCP
- UDP `3478` for TURN
- TCP `5349` for TURN/TLS
- UDP `50000-60000` for WebRTC media

LiveKit uses host networking so it can advertise the VPS public address and bind
the media ports. Restrict SSH to trusted administrators. Monitor CPU and network
egress; group calls and TURN-relayed media consume VPS bandwidth.

After provisioning and certificate setup:

```text
docker compose up -d --build
docker compose logs -f livekit call-api caddy
```

Verify `https://api.calls.example.com/healthz` returns `{"ok":true}`. Then
create a room with `POST /api/rooms`, and use the returned invitation code with
`POST /api/token` plus a display name. The API intentionally has no anonymous
room-directory endpoint; invitations are 192-bit random capabilities and expire
after four hours. Its in-memory invitations are invalidated if the API restarts.

## Local checks

Requires Node.js 20+:

```text
npm ci
npm test
```

The Android client has an initial LiveKit room screen with voice/video controls,
roster/tile layout, invitation-backed encrypted chat, and chunked encrypted file
transfer. A debug APK builds, but still needs testing on real devices against a
deployed call service before it is suitable for friend testing or release. The
iOS and Windows clients still need LiveKit interoperability; iOS release signing
requires Xcode on macOS. No cross-platform calling should be advertised until
those clients, the deployed service, and end-to-end tests are complete.
