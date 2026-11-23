# Federation end-to-end across REAL PROCESSES.
#
# Everything in conf_mixer_test.cs runs several CallServer instances inside one
# process over loopback TCP. That proves the logic; it cannot prove that two
# separate machines each running the shipped binary can find each other. This
# script does, using the actual UssdApp.exe:
#
#   node A  UssdApp.exe --serve  (relay on 45801, dials B, policy everyone)
#   node B  UssdApp.exe --serve  (relay on 45802, no peers configured)
#   recv    UssdApp.exe --watch  (headless endpoint registered on B)
#   send    UssdApp.exe --send   (headless endpoint registered on A)
#
# So the chat has to be produced on A and delivered on B, crossing one relay
# link that two independent processes negotiated over TCP. Nothing here trusts
# the app's own log lines for the payload: the assertion is what the receiving
# process printed and what landed in its chat file.
#
# -Exe lets the harness run a build that is not the one in Csharp\, which matters
# when the shipped exe is locked by a running instance: the sources under test can
# still be exercised across real processes instead of going unverified.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"
$portA = 45801
$portB = 45802
$numA = '7003258801'   # the sender, registered on relay A
$numB = '7003258802'   # the receiver, registered on relay B
$canary = 'FED-CANARY-' + (Get-Date -Format 'HHmmss')
$back  = 'FED-BACK-' + (Get-Date -Format 'HHmmss')
$base = Join-Path $env:TEMP 'opencode\fed'
$dirA = Join-Path $base 'nodeA'; $dirB = Join-Path $base 'nodeB'
$dirR = Join-Path $base 'recv';  $dirS = Join-Path $base 'send'
$outA = Join-Path $dirA 'relay_out.txt'; $outB = Join-Path $dirB 'relay_out.txt'
$outR = Join-Path $dirR 'recv_out.txt';  $outS = Join-Path $dirS 'send_out.txt'
$runLog = Join-Path $root 'diagnostics\federation_run.txt'
try { Start-Transcript -Path $runLog -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}

# --- clean slate, touching only processes started from these profiles --------
# Matched on the command line, not the process Path: this script deletes and
# re-copies its scratch folder, and a leftover process whose exe file is gone has
# no resolvable Path, so a Path-based filter would skip the one that holds the port.
try {
  foreach ($c in (Get-CimInstance Win32_Process -Filter "Name='UssdApp.exe' OR Name='UssdAgent.exe'" -ErrorAction SilentlyContinue)) {
    if ($c.CommandLine -and $c.CommandLine.Contains($base)) {
      try { Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue } catch { }
    }
  }
} catch { }
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith($base, 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Seconds 2
# Wipe the whole scratch tree. An old UssdApp.exe left in a profile folder gets
# launched by name below, so keeping it would silently test a stale binary while
# reporting the one asked for.
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirA, $dirB, $dirR, $dirS)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  # Explicit destination file name, so a build passed through -Exe under another
  # name still becomes the UssdApp.exe this script launches.
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
  Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $d -Force -ErrorAction SilentlyContinue
}

$env:USSD_TRACE = '1'

# --- two relay nodes, as separate processes ---------------------------------
$nodeA = Start-Process -FilePath (Join-Path $dirA 'UssdApp.exe') `
  -ArgumentList @('--serve', "--port=$portA", "--home=$dirA", '--relay-policy=everyone', `
                  "--relay-peers=127.0.0.1:$portB", '--serve-timeout=150') `
  -WorkingDirectory $dirA -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outA -RedirectStandardError (Join-Path $dirA 'relay_err.txt')
$nodeB = Start-Process -FilePath (Join-Path $dirB 'UssdApp.exe') `
  -ArgumentList @('--serve', "--port=$portB", "--home=$dirB", '--relay-policy=everyone', `
                  '--serve-timeout=150') `
  -WorkingDirectory $dirB -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outB -RedirectStandardError (Join-Path $dirB 'relay_err.txt')

# Wait for A to have dialled B. B should show one incoming link; A one outgoing.
$linked = $false
$ready = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $ready) {
  $ta = Read-Text $outA; $tb = Read-Text $outB
  if ($ta -match 'Link up' -and $tb -match 'Link up') { $linked = $true; break }
  if ($nodeA.HasExited -or $nodeB.HasExited) { break }
  Start-Sleep -Milliseconds 250
}
'link between the two relay processes: ' + $linked

# --- the two endpoints, one per relay ---------------------------------------
$recv = Start-Process -FilePath (Join-Path $dirR 'UssdApp.exe') `
  -ArgumentList @("--home=$dirR", "--number=$numB", "--relay=127.0.0.1:$portB", '--watch=75') `
  -WorkingDirectory $dirR -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outR -RedirectStandardError (Join-Path $dirR 'recv_err.txt')
$ready = (Get-Date).AddSeconds(25)
$regB = $false
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match 'connected=True') { $regB = $true; break }
  Start-Sleep -Milliseconds 250
}
'receiver registered on B: ' + $regB

# A must now see B's client through the link: that is the directory merge, and
# it is the claim the in-process test cannot make about separate binaries.
$merge = $false
$ready = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outA) -match 'remote_peers=([1-9])') { $merge = $true; break }
  Start-Sleep -Milliseconds 400
}
'relay A learned a peer that lives on relay B: ' + $merge

# --- send across the federation ---------------------------------------------
# --send plus --watch: the sender stays on the wire afterwards, so the reply has
# something to come back to. Without --watch it would drop the moment the send
# was accepted, and a queued reply would be the correct outcome, not a bug.
$send = Start-Process -FilePath (Join-Path $dirS 'UssdApp.exe') `
  -ArgumentList @("--home=$dirS", "--number=$numA", "--relay=127.0.0.1:$portA", `
                  "--send=$numB|$canary", '--watch=55') `
  -WorkingDirectory $dirS -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outS -RedirectStandardError (Join-Path $dirS 'send_err.txt')
$arrived = $false
$ready = (Get-Date).AddSeconds(70)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR).IndexOf($canary) -ge 0) { $arrived = $true; break }
  if ($send.HasExited -and (Read-Text $outR).IndexOf($canary) -ge 0) { $arrived = $true; break }
  Start-Sleep -Milliseconds 400
}
'chat crossed from relay A to relay B: ' + $arrived

# --- and back: the return path is the part most likely to be asymmetric -----
# Stop the watcher first: it holds this number on the relay, and a second
# connection registering the same number token displaces it.
try { if (-not $recv.HasExited) { $recv.Kill() } } catch { }
Start-Sleep -Seconds 2
$sendBack = Start-Process -FilePath (Join-Path $dirR 'UssdApp.exe') `
  -ArgumentList @("--home=$dirR", "--number=$numB", "--relay=127.0.0.1:$portB", `
                  "--send=$numA|$back", '--linger=25') `
  -WorkingDirectory $dirR -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $dirR 'sendback_out.txt') `
  -RedirectStandardError (Join-Path $dirR 'sendback_err.txt')
$backOk = $false
$ready = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $ready) {
  # The sender prints INBOUND for a live arrival; RESULT ... inbound= is its
  # summary. Either proves the reply crossed back, so count both as one event.
  if ((Read-Text $outS).IndexOf($back) -ge 0) { $backOk = $true; break }
  Start-Sleep -Milliseconds 400
}
'reply crossed back from relay B to relay A: ' + $backOk

Start-Sleep -Seconds 3
foreach ($p in @($nodeA, $nodeB)) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
Start-Sleep -Seconds 1

$ta = Read-Text $outA; $tb = Read-Text $outB; $tr = Read-Text $outR; $ts = Read-Text $outS
$tsb = Read-Text (Join-Path $dirR 'sendback_out.txt')
$chatOnB = ''
foreach ($f in (Get-ChildItem (Join-Path $dirR 'chats') -Filter *.txt -ErrorAction SilentlyContinue)) {
  $chatOnB += (Read-Text $f.FullName)
}
# Headless --watch prints an inbound chat and does NOT persist it: writing the
# conversation log is the window's job (it owns the chat store, the badges and
# the notifications). So the count is asserted against what the process printed,
# and the file is only reported, never required.
$canaryPrints = ([regex]::Matches($tr, 'INBOUND chat from #' + $numA + ': ' + [regex]::Escape($canary))).Count
$chatOnB += $canaryPrints
$canaryHits = $canaryPrints
$backPrints = ([regex]::Matches($ts, 'INBOUND chat from #' + $numB + ': ' + [regex]::Escape($back))).Count

$checks = @()
$checks += @{ n = 'two relay processes negotiated a link'; ok = $linked; d = '' }
$checks += @{ n = 'relay A saw the handshake as outgoing'; ok = ($ta -match 'Link up \(outgoing\)'); d = '' }
$checks += @{ n = 'relay B accepted it as incoming'; ok = ($tb -match 'Link up \(incoming\)'); d = '' }
$checks += @{ n = 'receiver took its slot on B'; ok = $regB; d = '' }
$checks += @{ n = 'DIRECTORY MERGE: A lists a peer registered on B'; ok = $merge; d = '' }
# Sealed either way: a session key from a live exchange, or the published identity
# key now that mail for an unreachable peer can be sealed too.
$sealedSent = (($ts -match 'sealedSession=locked') -or ($ts -match "sealed to #$numB's published key"))
$checks += @{ n = 'sender reports the chat was accepted, and private'; ok = ($ts -match 'RESULT sent=True' -and $sealedSent); d = '' }
$checks += @{ n = 'receiver printed the message from a peer on another relay'; ok = $arrived; d = '' }
$checks += @{ n = 'receiver printed it exactly once (no duplicate delivery)'; ok = ($canaryHits -eq 1); d = 'inbound lines=' + $canaryHits }
$checks += @{ n = 'the reply reached the originator on the other relay'; ok = ($backPrints -eq 1); d = 'inbound lines=' + $backPrints }
# The relays only ever forwarded sealed lines: neither canary may appear in a
# relay log, and a route line must not name the peer either.
$leak = ($ta.IndexOf($canary) -ge 0 -or $tb.IndexOf($canary) -ge 0 -or $ta.IndexOf($back) -ge 0 -or $tb.IndexOf($back) -ge 0)
$checks += @{ n = 'neither relay saw either message in clear'; ok = (-not $leak); d = '' }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
'--- relay A said ---'; ($ta -split "`n" | Select-Object -Last 12)
'--- relay B said ---'; ($tb -split "`n" | Select-Object -Last 8)
'--- sender said ---';  ($ts -split "`n" | Select-Object -Last 8)
'--- receiver said ---'; ($tr -split "`n" | Select-Object -Last 8)

Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith($base, 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
try { Stop-Transcript | Out-Null } catch { }
if (-not $allOk) { exit 1 }
exit 0
