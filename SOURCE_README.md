# USSD Manager Pro

Source for the Windows desktop application, Android and iOS clients, and the
calling service. This repository does not include app signing keys, local
device configuration, user message history, recordings, or runtime credentials.

## Build overview

- **Windows:** build with the .NET Framework 4 compiler using `Csharp\build.bat`.
  This project targets C# 5 and has no NuGet dependencies. Ensure `TEMP` points to
  an existing directory before building.
- **Android:** open `Mobile\Android` in Android Studio or run
  `gradlew.bat :app:assembleDebug` from that directory. A debug APK is not a
  production release.
- **iOS:** open `Mobile\iOS\UssdMobile.xcodeproj` on macOS with Xcode. An
  installable distribution requires Apple signing and provisioning configured
  locally or in a protected CI environment.
- **Calling service:** see `CallingServer\README.md`. Copy `.env.example` to a
  local `.env` and configure service credentials outside source control.

The download page and Render static-site manifest are in `website\`.

## Security and release status

Remote shell and unrestricted command execution are disabled. Do not re-enable
them; add only narrowly scoped, explicitly authorized in-app actions. Device
tracking uses authenticated pairing and foreground, user-triggered location
sharing.

No signed Windows, Android, or iOS production release is published yet. Do not
upload debug builds, private keys, relay identity files, device configs, or user
data as public release assets.
