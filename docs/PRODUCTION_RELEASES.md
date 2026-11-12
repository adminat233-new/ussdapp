# Production releases

`.github/workflows/production-release.yml` builds and verifies the signed
Windows bundle, Android APK, and Android App Bundle. It runs only for stable
`vMAJOR.MINOR.PATCH` tags, or when manually dispatched from `main` with an
existing stable tag. Preview tags continue to use
`.github/workflows/public-test-builds.yml`.

The user approved replacing the Windows zero-install-only call path with a
bundled Electron LiveKit companion; the complete runtime must ship in the
Windows ZIP. This changes the Windows distribution shape but leaves the
existing C#/.NET Framework app itself dependency-free.

Before creating a stable tag, configure these repository or protected
`production-release` environment secrets. Never commit signing material or
paste it into chat. Configure required reviewers on that environment if a
second-person release approval is desired.

| Secret | Purpose |
| --- | --- |
| `WINDOWS_SIGNING_PFX_BASE64` | Base64-encoded Authenticode code-signing PFX |
| `WINDOWS_SIGNING_PFX_PASSWORD` | Password for the Windows PFX |
| `ANDROID_SIGNING_KEYSTORE_BASE64` | Base64-encoded Android release/upload keystore |
| `ANDROID_SIGNING_STORE_PASSWORD` | Android keystore password |
| `ANDROID_SIGNING_KEY_ALIAS` | Signing key alias in the keystore |
| `ANDROID_SIGNING_KEY_PASSWORD` | Password for the Android signing key |

Use an organization-controlled Windows publisher certificate and preserve the
same Android upload key across releases. Losing or rotating the Android upload
key can block updates for users already installed from APKs; Google Play App
Signing can reduce store-key exposure, but the CI upload key must remain
protected. Protect production signing secrets with environment approval and
restrict who can create stable tags.

The Android stable release publishes a signed APK for direct installation and
an AAB for Play submission. The Windows stable release publishes a ZIP
containing `UssdApp.exe`, `UssdAgent.exe`, and the complete Electron LiveKit
companion under `USSDCalls/`. The WPF executable alone does not provide
cross-platform LiveKit calling.

These workflows sign and publish binaries; they do not prove a service is
deployed or that two real devices can call. Before claiming production-ready
calling, test a Windows device and Android device against the deployed calling
service on independent networks. Tracker actions remain unavailable until the
separate tracker service implements target-side, per-session approvals.
