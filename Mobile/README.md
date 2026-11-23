# USSD Manager Pro — Android & iOS Mobile App

Source tree for the mobile clients of USSD Manager Pro v4.0.6.6.

> **Verification status:** the Windows build and its regression suites are
> verified on this machine. No `dart`, `flutter`, `swiftc`, or `xcodebuild`
> toolchain was available here, so the Flutter and Swift changes in this tree
> are **source-level work, not compiler- or device-verified builds**. See
> [CAPABILITY_BOUNDARIES.md](../docs/CAPABILITY_BOUNDARIES.md) before relying on
> any claim below.

## Build requirements

- Flutter 3.10+ / Dart 3.0+
- Android Studio / Xcode
- NDK 25+ for Android
- Xcode 15+ for iOS

## Quick start

```bash
flutter pub get
flutter run -d android
flutter run -d ios
flutter build apk --release --target-platform android-arm64
flutter build ipa --release
```

These commands were not run in the verification environment. The checked-in
`android/` project currently builds native views and does not host the Dart
screens; the Dart UI and its MethodChannel bridges are source-level until that
embedding mismatch is resolved. The native Android/iOS apps have their own
implementations of the panels.

## What the sources actually do

### Windows (verified)

The desktop Apps page has a **Collaborated Apps** shelf that opens the real
FIND Laptop Tracker `.exe`, the FIND Android `.apk`, and the USSD Manager Calls
`.exe` through configured paths or bounded discovery. Each launch is an
explicit click; the tracker keeps its own consent prompts.

### Flutter source (not compiled here)

- **Dialer / relay** — `RelayService` speaks the line protocol used by
  `CallServer.cs`. `700XXXXXXX` numbers do not require a SIM.
- **Calls** — `WebRtcCallService` sends offer/answer/ICE over `WRTC|` relay
  signalling and carries media directly with WebRTC/ICE. `WRTC|` frames are
  isolated from chat and unread counts. STUN is on by default; TURN is optional
  and stored securely. Without TURN, calls can fail across symmetric NAT or
  strict firewalls.
- **Chat** — plain `CHAT|` over `MSG` for online peers. It is **not** described
  as end-to-end encrypted or store-and-forward: the relay refuses to store
  unsealed mail for absent peers. The native Windows/iOS sealed paths are
  separate implementations.
- **Apps** — a Collaborated Apps shelf calls
  `com.ussdapp.mobile/apps` `openPartnerApp` / `browsePartnerApp`. If the host
  has no bridge, the UI says so instead of pretending an app launched.
- **SIM Manager** — `DeviceTelemetryService` reports device model/OS and asks a
  native channel for carrier data. ICCID, IMSI, IMEI, signal, and AT modem
  telemetry stay explicitly unavailable on ordinary mobile OSes. The
  simulation toggle is labelled as simulation.
- **Agent** — provider, endpoint, model, read-aloud, and the BYOK secret are
  persisted with SharedPreferences/secure storage. Read-aloud calls a native
  speech channel and reports failure honestly. No AGI or ASI is implemented or
  claimed.
- **Call settings** — Settings > Calls stores TURN URL/user/credential and
  states plainly that no app can guarantee every network type.

### Native iOS source (not compiled here)

The SwiftUI app keeps its own dialer, LiveKit/CallingServer call centre, chat,
tracker, Apps shelf, SIM panel, and agent. CoreTelephony supplies the carrier
name when iOS exposes it; no SIM/IMEI secrets are invented. The Collaborated
Apps cards try custom URL schemes only when tapped and cannot launch a Windows
`.exe`.

## Architecture

```
RelayService (TCP, same line protocol as CallServer.cs)
    |
    +-- CHAT| / normal relay MSG -> chat panels
    +-- WRTC| base64 signalling  -> WebRtcCallService (Flutter source)
    `-- CONF_*                  -> conference panels

MainShell -> Dialer | Contacts | Video Call | SMS | SIM | USSD | Apps | Agent
```

## Honest boundaries

- Direct WebRTC in the Flutter source is **Flutter-to-Flutter only**. There is
  no common call signalling with the Windows 700-number stack or the iOS
  LiveKit stack, so cross-client media is not claimed.
- DERP is experimental; the post-quantum KEM is a placeholder.
- "Penetration impossible" is not claimed. The build contains specific,
  reviewable controls, not an absolute guarantee.
- The native Windows/iOS sealed-message paths and the Flutter plain-chat path
  are different; do not mix their capabilities in one claim.

Full details are in [CAPABILITY_BOUNDARIES.md](../docs/CAPABILITY_BOUNDARIES.md).
