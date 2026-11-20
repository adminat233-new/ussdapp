# USSD Manager Pro — Android & iOS Mobile App

Flutter implementation of USSD Manager Pro v4.1.  
Uses the same relay protocol as the Windows .exe.

## Build Requirements

- Flutter 3.10+ / Dart 3.0+
- Android Studio / Xcode
- NDK 25+ for Android
- Xcode 15+ for iOS

## Quick Start

```bash
# Install dependencies
flutter pub get

# Run on Android
flutter run -d android

# Run on iOS
flutter run -d ios

# Build release APK
flutter build apk --release --target-platform android-arm64

# Build release iOS IPA
flutter build ipa --release
```

## Features

- **Dialer** — Voice & video calls via relay, DTMF keypad
- **Chat** — End-to-end encrypted messaging, reactions, file transfer
- **Contacts** — Device + SIM contacts with groups
- **USSD** — MiFi HTTP API + relay AT commands  
- **Apps** — Laptop Tracker, OTP extractor, desktop bridge
- **Agent** — Local AI (Ollama) + cloud AI assistant
- **Background service** — Keeps relay alive when app is backgrounded
- **Push notifications** — Incoming calls & messages

## Architecture

```
RelayService (TCP socket, same line protocol as CallServer.cs)
    ↓
MainShell (bottom nav + app bar)
    ↓
DialerScreen | ChatScreen | ContactsScreen | UssdScreen | AppsScreen | AgentScreen
```

## Security

- Relay token derived deterministically per number; store proper random tokens in production
- Messages use the same E2E encryption as the desktop app (ECHAT sealed channel)
- Background service uses Android foreground service (shows notification — no silent spying)
