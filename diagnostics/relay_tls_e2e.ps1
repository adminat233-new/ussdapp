$ErrorActionPreference = "Stop"

$exe = if ($env:USSD_TLS_TEST_EXE) {
    $env:USSD_TLS_TEST_EXE
} else {
    Join-Path $PSScriptRoot "..\Csharp\UssdApp.exe"
}
if (-not (Test-Path -LiteralPath $exe)) { throw "Build UssdApp.exe before running this test." }

$base = Join-Path $env:TEMP ("ussd-relay-tls-" + [Guid]::NewGuid().ToString("N"))
$profileDir = Join-Path $base "profile"
$pfx = Join-Path $profileDir "relay_tls.pfx"
$log = Join-Path $base "relay.log"
$port = Get-Random -Minimum 46000 -Maximum 49000
$password = [Guid]::NewGuid().ToString("N")
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$oldPassword = $env:USSD_RELAY_TLS_PFX_PASSWORD
$certificate = $null
$server = $null

try {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $certificate = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" -KeyAlgorithm RSA -KeyLength 2048 `
        -NotAfter (Get-Date).AddDays(2)
    Export-PfxCertificate -Cert $certificate -FilePath $pfx -Password $securePassword | Out-Null
    $env:USSD_RELAY_TLS_PFX_PASSWORD = $password

    $arguments = @(
        "--serve", "--relay-tls", "--port=$port", "--home=$profileDir",
        "--relay-policy=everyone", "--serve-timeout=60"
    )
    $server = Start-Process -FilePath $exe -ArgumentList $arguments `
        -RedirectStandardOutput $log -PassThru -NoNewWindow

    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $log)) {
        Start-Sleep -Milliseconds 100
    }
    $ready = $false
    while ((Get-Date) -lt $deadline -and -not $server.HasExited) {
        if (Test-Path -LiteralPath $log) {
            $content = Get-Content -LiteralPath $log -Raw
            if ($content -match "RELAY UP .*transport=tls12") { $ready = $true; break }
            if ($content -match "RELAY FAIL") { throw "TLS relay failed to start: $content" }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) {
        $content = if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Raw } else { "" }
        throw "TLS relay did not become ready: $content"
    }

    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect("localhost", $port)
    $client.ReceiveTimeout = 5000
    $thumbprint = $certificate.Thumbprint
    $validateCertificate = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $cert, $chain, $errors)
        return $cert -ne $null -and $cert.GetCertHashString() -eq $thumbprint -and
            (($errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -eq 0)
    }
    $stream = New-Object -TypeName System.Net.Security.SslStream `
        -ArgumentList @($client.GetStream(), $false, $validateCertificate)
    try {
        $stream.AuthenticateAsClient("localhost")
        $writer = New-Object -TypeName System.IO.StreamWriter `
            -ArgumentList @($stream, [System.Text.Encoding]::UTF8)
        $reader = New-Object -TypeName System.IO.StreamReader `
            -ArgumentList @($stream, [System.Text.Encoding]::UTF8)
        $writer.AutoFlush = $true
        $writer.WriteLine("WHOAMI|")
        $identity = $reader.ReadLine()
        if ($identity -notmatch "^RPUB\|") { throw "TLS relay identity response was unexpected: $identity" }
        $writer.WriteLine("REG|7000000091|tls-test-token|tls-e2e")
        $registered = $reader.ReadLine()
        if ($registered -ne "OK|7000000091") { throw "TLS registration failed: $registered" }
    }
    finally {
        $stream.Dispose()
        $client.Close()
    }
    Write-Output "PASS TLS 1.2 handshake, pinned certificate/hostname check, relay identity, and registration"

    $mismatch = New-Object System.Net.Sockets.TcpClient
    $mismatch.Connect("127.0.0.1", $port)
    $script:tlsTestMismatchErrors = [System.Net.Security.SslPolicyErrors]::None
    $rejectMismatchedHost = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $cert, $chain, $errors)
        $script:tlsTestMismatchErrors = $errors
        return $false
    }
    $mismatchStream = New-Object -TypeName System.Net.Security.SslStream `
        -ArgumentList @($mismatch.GetStream(), $false, $rejectMismatchedHost)
    $mismatchRejected = $false
    try {
        $mismatchStream.AuthenticateAsClient("127.0.0.1")
    }
    catch [System.Security.Authentication.AuthenticationException] {
        $mismatchRejected = $true
    }
    finally {
        $mismatchStream.Dispose()
        $mismatch.Close()
    }
    if (-not $mismatchRejected -or
        (($script:tlsTestMismatchErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -eq 0)) {
        throw "TLS did not report and reject a certificate with the wrong hostname."
    }
    Write-Output "PASS TLS rejects a certificate hostname mismatch"

    $plain = New-Object System.Net.Sockets.TcpClient
    $plain.Connect("localhost", $port)
    $plain.ReceiveTimeout = 5000
    $plainStream = $plain.GetStream()
    $plainBytes = [System.Text.Encoding]::ASCII.GetBytes("WHOAMI|`n")
    $plainStream.Write($plainBytes, 0, $plainBytes.Length)
    $plainStream.Flush()
    $plainRejected = $false
    try { $plainResult = $plainStream.ReadByte(); $plainRejected = ($plainResult -eq -1) }
    catch [System.IO.IOException] { $plainRejected = $true }
    $plain.Close()
    if (-not $plainRejected) { throw "TLS relay accepted a cleartext protocol line." }
    Write-Output "PASS TLS listener rejects cleartext protocol traffic"
}
finally {
    if ($server -ne $null -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit()
    }
    if ($certificate -ne $null) {
        $thumbprint = $certificate.Thumbprint
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $thumbprint) -ErrorAction SilentlyContinue
    }
    if ($null -eq $oldPassword) {
        Remove-Item Env:\USSD_RELAY_TLS_PFX_PASSWORD -ErrorAction SilentlyContinue
    } else {
        $env:USSD_RELAY_TLS_PFX_PASSWORD = $oldPassword
    }
    if (Test-Path -LiteralPath $base) {
        Remove-Item -LiteralPath $base -Recurse -Force
    }
}
