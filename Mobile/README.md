# Mobile protocol clients

This folder contains platform-isolated Android and iOS app projects. It does
not change the Windows build: the Windows project continues to compile the
explicit source list in `Csharp\build.bat`.

## Wire contract

The clients use the existing UTF-8, newline-terminated relay protocol:

- `REG|number|token|machine|identityPub|signature`
- `KA|`
- `MSG|to|from|line`
- `RM|to|from|base64`
- `QUIT|`

The Android project includes a native assistant screen, durable offline queue,
and feature interfaces for voice/video, group calls, encrypted file transfer,
and notifications. The iOS project includes a SwiftUI shell, durable offline
queue, privacy strings, and equivalent feature interfaces.

Both app shells now include a local `/agent` command surface with
user-triggered speech recognition and text-to-speech. Supported commands are
`/agent help`, `/agent status`, `/agent say <text>` (up to 500 characters),
and `/agent <question>` for a configured AI model.
Voice commands require a configurable wake name and are captured only after
the user taps the listen button; neither app keeps a microphone open in the
background. Android uses the installed OS speech service (its offline
preference may not be honored by every provider) and the system TTS engine.
iOS requires on-device speech recognition support for the current language.
The AI path uses Google's Gemini Developer API with the default
`gemini-2.5-flash` model. Users must provide their own API key; Android stores
it encrypted with an Android Keystore AES-GCM key, and iOS stores it in the
device Keychain. The key is sent in an HTTPS request header and is not embedded
in the app. A provider may offer free quota, but neither an API key nor
permanent free access is bundled or guaranteed. Prompts are sent to Google
only when the user explicitly submits them. Local commands remain available
without an API key. The model cannot invoke tracker actions, shell commands,
or remote device control.

Both mobile apps include an explicit Device Tracking session for the external
`laptop-tracker` service's authenticated `/api/v2/*` routes. Pairing returns a
per-device bearer token; Android protects it with Android Keystore-backed
AES-GCM, and iOS stores it in the device-only Keychain. Authenticated status,
heartbeat, and lost-mode actions require the paired device's token. Pairing
codes are shown for device pairing; device tokens are stored securely and
redacted from tracker response output. Authenticated requests send the saved
token as a Bearer authorization credential. The legacy `/api/*` routes remain available to existing
tracker clients, but these mobile app screens do not call them.

Actions run only when the user taps them and require HTTPS. Status check-in
sends no coordinates. Paired-device reports show their last-known status and
timestamps; when two locations are available, the app can open both in a
user-selected map app. This is not a live map. A separate **Share current location once** action
requires foreground location permission and requests a single location fix
only after the user taps it; that fix is then sent to the configured tracker
using the authenticated heartbeat route. Denying permission, turning off
location, or failing to obtain a fix sends no coordinates. Neither platform
requests background location permission or starts background tracking. No
hidden capture, background autostart, or remote-shell execution path is added.
Lost mode is a server-side status flag only; it does not lock or command a
device. The tracker service's v2 schema migration must be applied and the Prisma client
regenerated before these routes can work in a deployment; no live migration
was applied as part of this change.

The registration signature must be an identity proof over:

```text
OWNS|<number>
```

The relay's `OK|` and `ERR|` responses are surfaced to the caller. Both mobile
clients now create per-app-number RSA-2048 identities in Android Keystore or
iOS Keychain, publish signed `PUBK` keys, request recipient keys with `PKQ`,
and send/accept only the Windows `ECHATK` sealed-mail envelope for chat. This
seals content to the public key the relay publishes; it provides authenticated
peer identity only after the user has independently verified the fingerprint.
The mobile chat screens accept an explicit relay host, port, app number, and token;
they do not scan networks or request device location, MAC, or DNS data.

The `ECHATK` format matches the existing Windows envelope: RSA-OAEP/SHA-1 key
wrapping, AES-128-CTR encryption, a truncated HMAC-SHA-256 authentication tag,
and an RSA/SHA-256 signature. New peer keys are pinned locally on first use
with a warning to verify the fingerprint out of band. Until that verification,
a malicious relay or on-path attacker can substitute a first-seen public key.
A changed key blocks messaging; there is no key-change override. Messages
waiting on a peer key remain in memory only. This compatibility code has local
envelope/tamper checks, but it has not yet been exercised against a live Windows executable
and relay, so do not treat cross-platform delivery as proven.

This is secure in-app text chat, not carrier SMS. Mobile relay connections use
TLS and validate the certificate chain and hostname using the platform trust
store. The Windows relay supports the same TLS 1.2 transport. Mobile clients do
not offer a cleartext fallback. Use a DNS name present in the relay certificate;
an IP address works only when the certificate has that IP in its subject
alternative names. Never bypass a certificate warning.

To host a TLS relay, place a currently valid server certificate with its private
key in `relay_tls.pfx` under the relay profile and enable **Require authenticated
TLS 1.2** in relay settings (or start the headless relay with `--relay-tls`).
Set `USSD_RELAY_TLS_PFX_PASSWORD` to the PFX password; TLS hosting refuses to
start without it. The certificate chain must be trusted by each connecting
device. For a private CA, install that CA into the device's trusted certificate
store before connecting. Windows clients use `tls://hostname:port`; federation
links use the same `tls://` endpoint form. Existing plain-TCP relay hosting is
still available for legacy Windows clients, but it does not protect relay
credentials and should not be used on untrusted networks. TLS changes take
effect by restarting the hosted relay; clients and links must reconnect using
TLS endpoints.

## Security boundary

These are transport and assistant foundations, not finished store
applications. They do not silently request contacts, location, microphone,
camera, Bluetooth, or local network access. Speech permission is requested
only after the user starts voice input; a platform UI must request other
permissions only when the corresponding feature starts.

The current Windows identity format is RSA public-key XML plus RSA/SHA-256
signatures. The mobile clients emit that format using platform-managed RSA
keys. Android Keystore hardware backing depends on the device; iOS identity
keys are device-only Keychain items. First-seen key pinning does not establish
out-of-band identity by itself.

## Validation status

Run `pwsh -NoProfile -File Mobile\validate.ps1` for the cross-platform source
contract checks and `Mobile\Android\gradlew.bat :app:assembleDebug` to build the
Android debug APK. The Android Gradle build and contract checks pass in the
current development environment. The protocol envelope also has a JVM test for
round-trip, wrong-recipient, invalid signature, and authenticated-ciphertext
tampering cases.

The public preview workflow attaches the Windows EXE and Android debug APK to
GitHub releases created from `v*-preview` tags; the static website enables
download buttons from those assets. A published release is required before
downloads are available. These builds are not production app-store packages.
Actual relay and Windows-app interoperability has not been run; emulator and
device validation is outstanding. iOS requires Xcode on macOS, so Swift
compilation, signing, permission prompts, and device tests remain outstanding.
Mobile voice/video calling is not interoperable: Windows uses authenticated
custom signaling and encrypted UDP media, for which mobile has no compatible
call/media engine. Push notifications and carrier SMS are also not implemented.
