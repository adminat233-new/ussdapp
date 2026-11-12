# Windows LiveKit calls

This companion uses the same LiveKit invitation/token API as Android. It is
packaged with Electron because the existing Windows application targets .NET
Framework 4.0/C# 5 and has no compatible LiveKit/WebRTC media client. This is
an explicit dependency/packaging change: download and install the complete
Windows release ZIP, which contains both the WPF app and this companion.

The call client creates and joins voice/video rooms only after the user acts.
The calling service URL must use HTTPS, except localhost during local
development. Its microphone/camera is used only while in a call. A call
invitation contains the shared call-room secret and must be treated like an
access credential. Media uses encrypted transport, but is not app-level
end-to-end encrypted; the LiveKit service can process media.

## Development

Requires Node.js 20+:

```text
npm ci
npm test
npm run build
npm start
```

For a Windows release folder:

```text
npm run pack:win
```

The resulting `release/win-unpacked` folder must be shipped beside
`UssdApp.exe`; do not distribute only `USSDCalls.exe` if the Electron runtime
files are absent. Configure the calling service as described in
`CallingServer/README.md`. Cross-device calling is not production-verified
until an Android device and this Windows companion join the same deployed
LiveKit room in a real-network test.
