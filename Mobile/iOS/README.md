# iOS app

Open `UssdMobile.xcodeproj` with Xcode on macOS. The project resolves the LiveKit Swift SDK and SwiftUI components through Swift Package Manager and targets iOS 16 or later.

The Calls screen uses the CallingServer `/api/rooms` and `/api/token` endpoints. Configure the service's HTTPS URL in the app, deploy the calling API and LiveKit media server, and use invitations only with people you trust. The invitation includes the key for encrypted in-call chat and file data; voice and video are encrypted in transit but are not app-level end-to-end encrypted.

The call screen supports voice/video start, invitation join/share, microphone and camera toggles during a call, adaptive participant video tiles, encrypted chat, and encrypted file transfer up to 50 MB. The app enables iOS background audio so an active voice call can continue when the app is backgrounded; camera/video availability while backgrounded is controlled by iOS. It is not yet a signed or device-tested release. Building, signing, and runtime verification require macOS/Xcode and Apple signing credentials.

## GitHub Actions builds and distribution

`.github/workflows/ios-ci.yml` builds the iOS Simulator target on changes to this project. It does not use signing credentials and does not produce an installable iPhone app.

`.github/workflows/ios-release.yml` is manually started from the `main` branch with one of three channels:

- **TestFlight:** archives and uploads the signed IPA to App Store Connect. Apple processing and TestFlight tester setup still happen in App Store Connect.
- **App Store:** uploads the signed IPA to App Store Connect for the normal App Store review and release process. The workflow does not submit the app for review or release it automatically.
- **Ad Hoc:** exports an IPA for the devices included in its provisioning profile and uploads it to a separate private GitHub repository. Do not make that repository public; the IPA contains a profile identifying registered test devices.

Configure these as **Actions secrets in a GitHub Environment named `ios-release`**. Do not commit certificate, profile, API-key, or device-registration files.

The workflow uses `com.ussdapp.mobile` by default. If your Apple Developer team does not own that bundle identifier, set the environment variable `IOS_BUNDLE_IDENTIFIER` and create matching provisioning profiles for the identifier you own.

Required secrets for all channels:

- `IOS_TEAM_ID`
- `IOS_CERTIFICATE_P12_BASE64` — base64-encoded Apple Distribution `.p12`
- `IOS_CERTIFICATE_PASSWORD`

For TestFlight and App Store:

- `IOS_APP_STORE_PROFILE_BASE64` — base64-encoded App Store provisioning profile for `com.ussdapp.mobile`
- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_ISSUER_ID`
- `APP_STORE_CONNECT_API_PRIVATE_KEY` — contents of the App Store Connect `.p8` key

For Ad Hoc:

- `IOS_ADHOC_PROFILE_BASE64` — base64-encoded Ad Hoc profile for `com.ussdapp.mobile`, with the intended tester devices registered
- `IOS_ADHOC_DESTINATION_REPOSITORY` — `owner/repository` of a separate **private** repository
- `IOS_ADHOC_DESTINATION_TOKEN` — fine-grained token restricted to that repository with Contents read/write permission

The source repository token is read-only in the workflow. The Ad Hoc token is used only in the Ad Hoc delivery step, which verifies that its destination repository is private before uploading the IPA. Rotate any signing or API credentials that are exposed outside GitHub's protected secret settings.
