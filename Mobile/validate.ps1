$ErrorActionPreference = "Stop"

$required = @(
    "README.md",
    "Android\settings.gradle",
    "Android\build.gradle",
    "Android\app\build.gradle",
    "Android\app\src\main\AndroidManifest.xml",
    "Android\app\src\main\java\com\ussdapp\mobile\MainActivity.kt",
    "Android\src\main\java\com\ussdapp\relay\GeminiAssistant.kt",
    "Android\src\main\java\com\ussdapp\relay\MobileAgent.kt",
    "Android\src\main\java\com\ussdapp\relay\RelayClient.kt",
    "Android\src\main\java\com\ussdapp\relay\MobileIdentityCrypto.kt",
    "Android\src\main\java\com\ussdapp\relay\AndroidRelayIdentity.kt",
    "Android\src\main\java\com\ussdapp\relay\WindowsSealedMessage.kt",
    "Android\src\main\java\com\ussdapp\relay\MobileMessagingSession.kt",
    "Android\SealedMessageCheck.kts",
    "Android\src\main\java\com\ussdapp\relay\TrackerClient.kt",
    "Android\src\main\java\com\ussdapp\relay\MobileFeatures.kt",
    "iOS\RelayIdentity.swift",
    "iOS\RelayClient.swift",
    "iOS\WindowsSealedMessage.swift",
    "iOS\MobileMessagingSession.swift",
    "iOS\MobileMessagingView.swift",
    "iOS\TrackerClient.swift",
    "iOS\MobileFeatures.swift",
    "iOS\GeminiAssistant.swift",
    "iOS\MobileAgent.swift",
    "iOS\UssdMobileApp.swift",
    "iOS\Info.plist"
)

foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $relative))) {
        throw "Missing mobile source: $relative"
    }
}

$android = Get-Content -Raw (Join-Path $PSScriptRoot "Android\src\main\java\com\ussdapp\relay\RelayClient.kt")
$ios = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\RelayClient.swift")
if ($android -notmatch "REG\|" -or $ios -notmatch "REG\|") {
    throw "Registration contract is missing"
}
if ($android -notmatch "ECHATK\|" -or $ios -notmatch "ECHATK\|") {
    throw "Windows-compatible sealed-message gate is missing"
}
if ($android -notmatch "ECHAT\|" -or $ios -notmatch "ECHAT\|") {
    throw "Encrypted message gate is missing"
}
if ($android -match "(^|[^E])CHAT\|" -or $ios -match "(^|[^E])CHAT\|") {
    throw "Plaintext chat path is present"
}
if ($android -notmatch "signOwnsClaim" -or $ios -notmatch "signOwnsClaim") {
    throw "Identity proof gate is missing"
}
if ($android -notmatch "SSLSocketFactory" -or
    $android -notmatch "getDefaultHostnameVerifier" -or
    $ios -notmatch "using: \.tls") {
    throw "Platform-validated relay TLS is missing"
}
$androidSeal = Get-Content -Raw (Join-Path $PSScriptRoot "Android\src\main\java\com\ussdapp\relay\WindowsSealedMessage.kt")
$androidSession = Get-Content -Raw (Join-Path $PSScriptRoot "Android\src\main\java\com\ussdapp\relay\MobileMessagingSession.kt")
$iosSeal = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\WindowsSealedMessage.swift")
$iosSession = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\MobileMessagingSession.swift")
$iosView = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\MobileMessagingView.swift")
if ($androidSeal -notmatch "OAEPWithSHA-1AndMGF1Padding" -or
    $androidSeal -notmatch "AES/CTR/NoPadding" -or
    $androidSeal -notmatch "HmacSHA256" -or
    $androidSeal -notmatch "fingerprint" -or
    -not $androidSeal.Contains('identity.sign("$VERB|$box")') -or
    -not $androidSeal.Contains('signature.update("PUBK|$number"') -or
    -not $androidSeal.Contains('verifier.update("$VERB|${fields[1]}"') -or
    -not $androidSession.Contains('identity.sign("PUBK|${identity.number}")') -or
    $androidSession -notmatch "verifyPublishedKey" -or
    $iosSeal -notmatch "rsaEncryptionOAEPSHA1" -or
    $iosSeal -notmatch "kCCModeCTR" -or
    $iosSeal -notmatch "fingerprint" -or
    -not $iosSeal.Contains('sign("PUBK|\(number)")') -or
    -not $iosSeal.Contains('Data("\(Self.verb)|\(fields[1])".utf8)') -or
    $iosSession -notmatch "verifyPublishedKey" -or
    $iosView -notmatch "Connect to relay" -or $iosView -notmatch "Send encrypted message") {
    throw "Cross-platform sealed chat implementation is incomplete"
}
$androidActivity = Get-Content -Raw (Join-Path $PSScriptRoot "Android\app\src\main\java\com\ussdapp\mobile\MainActivity.kt")
if ($androidActivity -notmatch "Connect to relay" -or
    $androidActivity -notmatch "Send encrypted message" -or
    $androidActivity -notmatch "MobileMessagingSession") {
    throw "Android secure chat user interface is incomplete"
}
$manifest = Get-Content -Raw (Join-Path $PSScriptRoot "Android\app\src\main\AndroidManifest.xml")
if ($manifest -match 'usesCleartextTraffic\s*=\s*"true"' -or
    $androidActivity -match "TCP, no TLS" -or $iosView -match "TCP, no TLS") {
    throw "Mobile relay must not permit or advertise cleartext transport"
}
$atr = Get-Content -Raw (Join-Path $PSScriptRoot "Android\src\main\java\com\ussdapp\relay\TrackerClient.kt")
$itr = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\TrackerClient.swift")
if ($atr -notmatch "/api/v2/pair/generate" -or $atr -notmatch "/api/v2/heartbeat" -or
    $atr -notmatch "Authorization" -or $atr -notmatch "AndroidKeyStore" -or
    $atr -match '"/api/(generate|verify|heartbeat|lost-mode)' -or
    $atr -notmatch "instanceFollowRedirects\s*=\s*false" -or
    $itr -notmatch "/api/v2/pair/generate" -or $itr -notmatch "/api/v2/heartbeat" -or
    $itr -notmatch "Authorization" -or $itr -notmatch "SecItemAdd" -or
    $itr -match '"/api/(generate|verify|heartbeat|lost-mode)' -or
    $itr -notmatch "completionHandler\(nil\)") {
    throw "Tracker API bridge surface is incomplete"
}
$androidActivity = Get-Content -Raw (Join-Path $PSScriptRoot "Android\app\src\main\java\com\ussdapp\mobile\MainActivity.kt")
$iosApp = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\UssdMobileApp.swift")
$plist = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\Info.plist")
if ($androidActivity -notmatch "Device tracking session" -or
    $androidActivity -notmatch "Send status-only check-in" -or
    $androidActivity -notmatch "Share current location once" -or
    $androidActivity -notmatch "TrackerCredentialStore" -or
    $androidActivity -notmatch "requestSingleUpdate" -or

    $androidActivity -notmatch "Open last reported location in Maps" -or
    $androidActivity -notmatch "TrackerClient" -or
    $androidActivity -notmatch 'uri\.scheme != "https"' -or
    $iosApp -notmatch "DeviceTrackingView" -or
    $iosApp -notmatch "Send status-only check-in" -or
    $iosApp -notmatch "Share current location once" -or
    $iosApp -notmatch "TrackerCredentialStore" -or
    $iosApp -notmatch "Last reported locations" -or
    $iosApp -notmatch "maps\.apple\.com" -or
    $iosApp -notmatch "requestWhenInUseAuthorization" -or
    $iosApp -notmatch 'components\.scheme == "https"' -or
    $manifest -notmatch "ACCESS_FINE_LOCATION" -or
    $manifest -notmatch "ACCESS_COARSE_LOCATION" -or
    $manifest -match "ACCESS_BACKGROUND_LOCATION" -or
    $plist -notmatch "NSLocationWhenInUseUsageDescription" -or
    $plist -match "NSLocationAlways") {
    throw "One-time consent-based location sharing is incomplete or requests background access"
}
$androidAgent = Get-Content -Raw (Join-Path $PSScriptRoot "Android\src\main\java\com\ussdapp\relay\MobileAgent.kt")
$androidAi = Get-Content -Raw (Join-Path $PSScriptRoot "Android\src\main\java\com\ussdapp\relay\GeminiAssistant.kt")
$androidActivity = Get-Content -Raw (Join-Path $PSScriptRoot "Android\app\src\main\java\com\ussdapp\mobile\MainActivity.kt")
$iosAgent = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\MobileAgent.swift")
$iosAi = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\GeminiAssistant.swift")
$iosApp = Get-Content -Raw (Join-Path $PSScriptRoot "iOS\UssdMobileApp.swift")
if ($androidAgent -notmatch 'handleText' -or $androidAgent -notmatch 'handleVoice' -or
    $androidAgent -notmatch '500' -or $androidActivity -notmatch 'RecognizerIntent' -or
    $androidActivity -notmatch 'TextToSpeech' -or $manifest -notmatch 'RECORD_AUDIO') {
    throw "Android user-triggered speech assistant is incomplete"
}
if ($iosAgent -notmatch 'requiresOnDeviceRecognition = true' -or
    $iosAgent -notmatch 'AVSpeechSynthesizer' -or $iosApp -notmatch 'startListening' -or
    $plist -notmatch 'NSSpeechRecognitionUsageDescription' -or
    $plist -notmatch 'NSMicrophoneUsageDescription') {
    throw "iOS on-device speech assistant or permission disclosure is incomplete"
}
if ($androidAgent -match 'Runtime\.getRuntime|ProcessBuilder|TrackerClient' -or
    $iosAgent -match 'Process\(|TrackerClient') {
    throw "Agent command path must not execute shell or tracker actions"
}
if ($androidAi -notmatch 'AndroidKeyStore' -or $androidAi -notmatch 'AES/GCM/NoPadding' -or
    $androidAi -notmatch 'x-goog-api-key' -or $androidAi -notmatch 'https://generativelanguage\.googleapis\.com' -or
    $androidActivity -notmatch 'Save API key securely' -or $androidActivity -notmatch 'askAi') {
    throw "Android BYOK AI client or secure key storage is incomplete"
}
if ($iosAi -notmatch 'SecItemAdd' -or $iosAi -notmatch 'SecItemUpdate' -or
    $iosAi -notmatch 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly' -or
    $iosAi -notmatch 'x-goog-api-key' -or
    $iosAi -notmatch 'https://generativelanguage\.googleapis\.com' -or
    $iosApp -notmatch 'SecureField' -or $iosAgent -notmatch 'askAI') {
    throw "iOS BYOK AI client or Keychain storage is incomplete"
}

Write-Output "MOBILE CONTRACT VALIDATION: PASS"
