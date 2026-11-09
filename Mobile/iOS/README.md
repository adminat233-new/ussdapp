# iOS app

Open `UssdMobile.xcodeproj` with Xcode on macOS. The project resolves the LiveKit Swift SDK and SwiftUI components through Swift Package Manager and targets iOS 16 or later.

The Calls screen uses the CallingServer `/api/rooms` and `/api/token` endpoints. Configure the service's HTTPS URL in the app, deploy the calling API and LiveKit media server, and use invitations only with people you trust. The invitation includes the key for encrypted in-call chat and file data; voice and video are encrypted in transit but are not app-level end-to-end encrypted.

The call screen supports voice/video start, invitation join/share, microphone and camera toggles during a call, adaptive participant video tiles, encrypted chat, and encrypted file transfer up to 50 MB. The app enables iOS background audio so an active voice call can continue when the app is backgrounded; camera/video availability while backgrounded is controlled by iOS. It is not yet a signed or device-tested release. Building, signing, and runtime verification require macOS/Xcode and Apple signing credentials.
