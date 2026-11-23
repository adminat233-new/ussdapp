# Capability boundaries and verification status

This document records what the current sources actually implement. It exists to
stop a UI label, a test double, or a planned feature from being read as a shipped
capability.

## Windows store shelf

The Windows Apps page has a **Collaborated Apps** shelf above the six-module
grid. Its cards point at the real FIND Laptop Tracker `.exe`, the FIND Android
`.apk`, and the USSD Manager Calls `.exe`. **Open** launches a configured path
or a bounded-discovery result; **Browse...** asks for a path. A found app is
marked installed. Launch is always a user action, and the tracker keeps its own
consent prompts. No hidden persistence, stealth mode, or remote shell is part of
this path.

## Calls and media

* Windows voice/video uses the existing UDP/TCP relay and 700-number signalling.
  Real media-route assertions count frames on the relay, because a loopback test
  cannot prove that media crossed a link.
* Flutter now contains a source-level `WebRtcCallService`: offer/answer/ICE
  signalling travels as `WRTC|<base64 JSON>` inside the relay `MSG` envelope,
  and media is direct WebRTC/ICE. `WRTC|` frames are delivered to call listeners
  only; they do not increment chat unread and do not appear in the SMS panel.
* TURN is user-configurable in **Settings > Calls**. STUN is enabled by default.
  Without TURN, symmetric NAT or strict firewalls can block media. **No version
  of this app claims calls work over every network type or distance.**
* There is **no common signalling protocol** between the Flutter WebRTC path,
  the Windows 700-number call stack, and the iOS LiveKit stack. A Flutter peer
  can call another Flutter peer; Flutter-to-Windows and Flutter-to-iOS media
  interoperability is not claimed.
* Real Windows microphone capture could not be verified on the build machine:
  `waveInOpen` returned `mmresult 1` and the OS microphone consent registry
  value was `Deny`. A synthetic `USSD_FAKE_MIC=1` hook exists only for harness
  control and is not evidence of a working microphone.

## Flutter/native host status

No `dart`, `flutter`, `swiftc`, or `xcodebuild` toolchain was available in the
verification environment, so all Dart and Swift changes are source-level work.
They were checked against tagged `flutter_webrtc` 0.10.0 and
`webrtc_interface` 1.2.x sources, **not** compiled here.

The checked-in Android project does not currently host the Dart screens:
`Mobile/android/app/build.gradle` has no Flutter embedding, and `MainActivity`
extends `Activity` and builds native views. The Dart screens and the new
MethodChannel bridges are therefore source-level until that structural mismatch
is resolved. The native Android/iOS apps continue to have their own call,
chat, tracker, and agent implementations.

## Chat, queueing, and relay sealing

The relay refuses to store unsealed mail. A plain `MSG` to an absent peer
returns `ERR|nokey`; only `ECHAT`/`ECHATK` sealed traffic is retained and
flushed on registration. The Windows client uses that sealed path and has an
offline chat/missed-call queue. The Flutter chat screen currently sends plain
`CHAT|` over `MSG` and does not claim offline mail delivery. Do not describe
Flutter chat as end-to-end encrypted or store-and-forward until it uses the
sealed protocol.

## Device telemetry

* Windows can read modem/SIM telemetry when a real modem is attached.
* `700XXXXXXX` app numbers are modem/SIM-free identities.
* Flutter `DeviceTelemetryService` reports device model/OS where available and
  asks a native channel for carrier data. Most mobile OSes deny ICCID, IMSI, and
  IMEI to ordinary apps; those fields remain explicitly unavailable.
* iOS uses CoreTelephony for carrier name when iOS exposes it. It does not read
  or invent ICCID, IMSI, IMEI, signal strength, or AT modem diagnostics.
* The SIM Manager simulation toggle is labelled as simulation and never
  represents a modem action.

## Agent and AI

Agent settings (provider, endpoint, model, read-aloud, and BYOK secret) are
persisted with SharedPreferences/secure storage in Flutter and with
UserDefaults/keychain in the native clients. Read-aloud calls a native speech
channel and reports failure honestly when no engine is attached. All remote
control tools remain command requests behind a local approval dialog. The
assistant is a deterministic command router plus an optional model call; no AGI
or ASI is implemented or claimed.

## Protocol caveats

* DERP is experimental and is labelled as such.
* The post-quantum KEM is an explicit placeholder, not a proven PQ exchange.
* There is no basis for claiming that penetration is impossible. The build
  contains specific, reviewable controls, not an absolute security guarantee.
