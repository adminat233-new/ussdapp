# Hostile-relay live proof.
#
# The selftest models a malicious relay; this one IS one. A dumb relay written in
# PowerShell (not part of the app) forwards traffic between two headless app
# instances and logs EVERY raw line it passes through. The claim being tested is
# narrow and checkable: the relay can move your messages but cannot read them.
#
# Asserts:
#   1. both instances mint a different per-install identity key;
#   2. the handshake crossed the relay (KEYX + KEYXOK on the wire);
#   3. the chat crossed the relay as ECHAT|<base64> only;
#   4. the canary phrase appears in the receiver's decrypted output and NOWHERE
#      in the relay's own log;
#   5. both sides report the same safety number.
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$exe = Join-Path $root 'Csharp\UssdSecTest.exe'
$port = 45690
$wire = Join-Path $root 'diagnostics\relay_wire.log'
$cDir = Join-Path $env:TEMP 'opencode\instC'
$dDir = Join-Path $env:TEMP 'opencode\instD'
$cOut = Join-Path $cDir 'out.txt'
$dOut = Join-Path $dDir 'out.txt'
$numC = '7003256311'
$numD = '7003256322'
$canary = 'CANARY-' + (Get-Date -Format 'HHmmss')

foreach ($d in @($cDir, $dDir)) {
  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
  # A fresh install: no identity key yet, so this run also proves the key is
  # created per install rather than baked into the binary.
  Remove-Item -Path (Join-Path $d 'identity.key') -ErrorAction SilentlyContinue
  Remove-Item -Path (Join-Path $d 'app_config.json') -ErrorAction SilentlyContinue
  Copy-Item $exe -Destination $d -Force
  Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $d -Force -ErrorAction SilentlyContinue
}

Set-Content -Path $wire -Value ("=== capture relay on 127.0.0.1:" + $port + ' ' + (Get-Date -Format 'o'))

$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
$listener.Start()
$clients = New-Object System.Collections.ArrayList

function Wire([string]$s) { Add-Content -Path $wire -Value ((Get-Date -Format 'HH:mm:ss.fff') + ' ' + $s) }

function Send-Line($c, [string]$line) {
  $b = [System.Text.Encoding]::UTF8.GetBytes($line + "`n")
  $c.Stream.Write($b, 0, $b.Length)
}

function Find-ByNum([string]$num) {
  foreach ($x in $clients) { if ($x.Num -eq $num) { return $x } }
  return $null
}

function Broadcast-Peers {
  $recs = @()
  foreach ($x in $clients) { if ($x.Num) { $recs += ($x.Num + ',127.0.0.1,relaytest') } }
  $payload = 'PEERS|' + ($recs -join ';')
  foreach ($x in $clients) { if ($x.Num) { Send-Line $x $payload } }
}

function Handle-Line($c, [string]$line) {
  if (-not $line) { return }
  # The app's StreamWriter emits a UTF-8 BOM on the first line of the stream;
  # a byte-level parser must strip it or the verb comparison silently fails.
  $line = $line.TrimStart([char]0xFEFF)
  if (-not $line) { return }
  Wire ('<- ' + $line)
  $p = $line -split '\|', 4
  if ($p[0] -eq 'REG') {
    $c.Num = $p[1].Trim()
    Send-Line $c ('OK|' + $p[1])
    Broadcast-Peers
  }
  elseif ($p[0] -eq 'KA') { }
  elseif ($p[0] -eq 'MSG' -or $p[0] -eq 'RM') {
    $t = Find-ByNum $p[1].Trim()
    if ($t) { Send-Line $t $line; Wire ('-> ' + $p[1] + ' forwarded (' + $line.Length + ' chars)') }
    else { Wire ('-> ' + $p[1] + ' OFFLINE, not forwarded') }
  }
  else { Wire ('  (ignored)') }
}

$deadline = (Get-Date).AddSeconds(50)

# The relay must run while both clients are connected, so the client processes
# are started first and the relay loop polls everything in one thread.
$env:USSD_FAKE_MIC = '1'
$psD = Start-Process -FilePath (Join-Path $dDir 'UssdSecTest.exe') `
  -ArgumentList @("--number=$numD", '--relay=127.0.0.1:45690', '--watch=30') `
  -WorkingDirectory $dDir -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $dOut -RedirectStandardError (Join-Path $dDir 'err.txt')
Start-Sleep -Seconds 3
$psC = Start-Process -FilePath (Join-Path $cDir 'UssdSecTest.exe') `
  -ArgumentList @("--number=$numC", '--relay=127.0.0.1:45690', "--send=$numD|$canary", '--linger=18') `
  -WorkingDirectory $cDir -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $cOut -RedirectStandardError (Join-Path $cDir 'err.txt')

while ((Get-Date) -lt $deadline) {
  # TcpListener.Pending() is the accept check; Socket.Pending() does not exist
  # in .NET Core and Socket.Available stays 0 on a listening socket.
  if ($listener.Pending()) {
    $tc = $listener.AcceptTcpClient()
    $tc.ReceiveTimeout = 0
    [void]$clients.Add([pscustomobject]@{ Tcp = $tc; Stream = $tc.GetStream(); Num = ''; Pending = '' })
    Wire ('+ connection from ' + $tc.Client.RemoteEndPoint)
  }
  foreach ($c in @($clients)) {
    try {
      if ($c.Stream.DataAvailable) {
        $buf = New-Object byte[] 16384
        $n = $c.Stream.Read($buf, 0, $buf.Length)
        if ($n -gt 0) {
          $c.Pending += [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
          while ($c.Pending.Contains("`n")) {
            $i = $c.Pending.IndexOf("`n")
            $line = $c.Pending.Substring(0, $i).TrimEnd("`r")
            $c.Pending = $c.Pending.Substring($i + 1)
            Handle-Line $c $line
          }
        }
      }
    } catch { Wire ('! read error: ' + $_.Exception.Message); $clients.Remove($c) | Out-Null }
  }
  if ($psC.HasExited -and $psD.HasExited) { break }
  Start-Sleep -Milliseconds 60
}

Start-Sleep -Seconds 2
foreach ($c in @($clients)) { try { $c.Tcp.Close() } catch { } }
try { $listener.Stop() } catch { }
try { $psC.WaitForExit(5000) | Out-Null; $psD.WaitForExit(8000) | Out-Null } catch { }

'=== C (sender) ==='
Get-Content $cOut
'=== D (receiver) ==='
Get-Content $dOut
'=== relay log: ' + (Get-Content $wire).Count + ' lines ==='

$wireAll = (Get-Content $wire) -join "`n"
$dAll = (Get-Content $dOut) -join "`n"
$cAll = (Get-Content $cOut) -join "`n"
$fpC = if ($cAll -match 'identity=([0-9A-F-]+)') { $Matches[1] } else { '?' }
$fpD = if ($dAll -match 'identity=([0-9A-F-]+)') { $Matches[1] } else { '?' }
$snC = if ($cAll -match 'Safety number: (\d[\d ]+\d)') { $Matches[1].Trim() } else { '' }
$snD = if ($dAll -match 'Safety number: (\d[\d ]+\d)') { $Matches[1].Trim() } else { '' }

$checks = @()
$checks += @{ n = 'different identity key per install'; ok = ($fpC -ne '?' -and $fpD -ne '?' -and $fpC -ne $fpD); d = "C=$fpC D=$fpD" }
$checks += @{ n = 'handshake crossed the relay'; ok = ($wireAll -match 'KEYX\|' -and $wireAll -match 'KEYXOK\|'); d = '' }
$checks += @{ n = 'chat crossed sealed as ECHAT'; ok = ($wireAll -match 'ECHAT\|'); d = '' }
$checks += @{ n = 'relay log never contains the canary'; ok = ($wireAll.IndexOf($canary) -lt 0); d = '' }
$checks += @{ n = 'receiver decrypted the canary'; ok = ($dAll.IndexOf($canary) -ge 0); d = '' }
$checks += @{ n = 'both sides show one safety number'; ok = ($snC.Length -gt 10 -and $snC -eq $snD); d = "C='" + $snC + "' D='" + $snD + "'" }
$checks += @{ n = 'sender reported a sealed session'; ok = ($cAll -match 'sealedSession=locked'); d = '' }

'=== verdict ==='
$all = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $all = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($all) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
if (-not $all) { exit 1 }
exit 0
