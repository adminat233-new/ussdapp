# Onion routing end-to-end across REAL PROCESSES.
#
# federation_e2e.ps1 proves two relays can carry a chat between them. That path
# has no intermediate: relay A talks to relay B directly, so there is nobody in
# the middle to hide anything from. This script adds the middle, because the
# privacy claim is only about a relay that carries traffic between two strangers:
#
#   nodeM  UssdApp.exe --serve  (45813, the hub: both leaves dial it)
#   nodeA  UssdApp.exe --serve  (45811, dials M, --relay-onion=force)
#   nodeB  UssdApp.exe --serve  (45812, dials M, --relay-onion=force)
#   recv   headless endpoint registered on B
#   send   headless endpoint registered on A
#
# A and B are never linked to each other, so every message between them crosses
# M. Both leaves run in FORCE mode, which refuses a message rather than forward
# it in clear - so if the layering did not work, the chat would simply never
# arrive and this script would fail instead of quietly passing on a leak.
#
# The assertions that matter are made about M: not what M chose to log about the
# message, but whether any single line M ever printed names both ends. A relay
# that knows which numbers live behind which peers is a phone book; a relay that
# can say "this one messaged that one" is a surveillance log, and that is the
# difference being measured here.
#
# -Exe runs a build that is not the one in Csharp\, which matters when the shipped
# exe is locked by a running instance.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"
$portA = 45811
$portB = 45812
$portM = 45813
$numA = '7003259901'   # sender, registered on relay A
$numB = '7003259902'   # receiver, registered on relay B
$canary = 'ONION-CANARY-' + (Get-Date -Format 'HHmmss')
$back = 'ONION-BACK-' + (Get-Date -Format 'HHmmss')
$base = Join-Path $env:TEMP 'opencode\onion'
$dirA = Join-Path $base 'nodeA'; $dirB = Join-Path $base 'nodeB'; $dirM = Join-Path $base 'nodeM'
$dirR = Join-Path $base 'recv';  $dirS = Join-Path $base 'send'
$outA = Join-Path $dirA 'relay_out.txt'; $outB = Join-Path $dirB 'relay_out.txt'
$outM = Join-Path $dirM 'relay_out.txt'
$outR = Join-Path $dirR 'recv_out.txt';  $outS = Join-Path $dirS 'send_out.txt'
$runLog = Join-Path $root 'diagnostics\onion_run.txt'
try { Start-Transcript -Path $runLog -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}
# Any single line that names both ends. Checked per line on purpose: the hub
# legitimately learns each number on its own, from the directory gossip.
function PairLines([string]$text) {
  $n = 0
  foreach ($ln in ($text -split "`r?`n")) {
    if ($ln.Contains($numA) -and $ln.Contains($numB)) { $n++ }
  }
  return $n
}

# --- clean slate, touching only processes started from these profiles --------
# Command line, not process Path: this script wipes and re-copies its scratch tree,
# and a leftover whose exe file is gone has no resolvable Path - which is the one
# still holding the port.
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
# Wipe the whole scratch tree: a stale UssdApp.exe in a profile folder would be
# launched by name below while the header reports a different binary.
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirA, $dirB, $dirM, $dirR, $dirS)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  # Explicit destination file name, so -Exe under another name still becomes the
  # UssdApp.exe this script launches.
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
  Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $d -Force -ErrorAction SilentlyContinue
}

$env:USSD_TRACE = '1'

# --- the hub first, then the two leaves that dial it -------------------------
$nodeM = Start-Process -FilePath (Join-Path $dirM 'UssdApp.exe') `
  -ArgumentList @('--serve', "--port=$portM", "--home=$dirM", '--relay-policy=everyone', `
                  '--serve-timeout=170') `
  -WorkingDirectory $dirM -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outM -RedirectStandardError (Join-Path $dirM 'relay_err.txt')
Start-Sleep -Milliseconds 800
$nodeA = Start-Process -FilePath (Join-Path $dirA 'UssdApp.exe') `
  -ArgumentList @('--serve', "--port=$portA", "--home=$dirA", '--relay-policy=everyone', `
                  "--relay-peers=127.0.0.1:$portM", '--relay-onion=force', '--serve-timeout=170') `
  -WorkingDirectory $dirA -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outA -RedirectStandardError (Join-Path $dirA 'relay_err.txt')
$nodeB = Start-Process -FilePath (Join-Path $dirB 'UssdApp.exe') `
  -ArgumentList @('--serve', "--port=$portB", "--home=$dirB", '--relay-policy=everyone', `
                  "--relay-peers=127.0.0.1:$portM", '--relay-onion=force', '--serve-timeout=170') `
  -WorkingDirectory $dirB -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outB -RedirectStandardError (Join-Path $dirB 'relay_err.txt')

$linked = $false
$ready = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $ready) {
  $ta = Read-Text $outA; $tb = Read-Text $outB; $tm = Read-Text $outM
  if ($ta -match 'Link up' -and $tb -match 'Link up' -and ($tm -match 'Link up \(incoming\)')) { $linked = $true; break }
  if ($nodeA.HasExited -or $nodeB.HasExited -or $nodeM.HasExited) { break }
  Start-Sleep -Milliseconds 250
}
'three relay processes, both leaves on the hub: ' + $linked

# --- the two endpoints, one per leaf ----------------------------------------
$recv = Start-Process -FilePath (Join-Path $dirR 'UssdApp.exe') `
  -ArgumentList @("--home=$dirR", "--number=$numB", "--relay=127.0.0.1:$portB", '--watch=90') `
  -WorkingDirectory $dirR -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outR -RedirectStandardError (Join-Path $dirR 'recv_err.txt')
$regB = $false
$ready = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match 'connected=True') { $regB = $true; break }
  Start-Sleep -Milliseconds 250
}
'receiver registered on relay B: ' + $regB

# A must learn a peer that sits two hops away, and the key that makes layering to
# it possible. Neither can come from a link A has: A is only linked to the hub.
$merge = $false
$ready = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outA) -match 'remote_peers=([1-9])') { $merge = $true; break }
  Start-Sleep -Milliseconds 400
}
'relay A learned, through the hub, a peer behind it: ' + $merge
$keysFile = Join-Path $dirA 'relay_keys.txt'
$pinned = $false
$ready = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $ready) {
  if (Test-Path $keysFile) {
    $lines = @((Get-Content $keysFile) | Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -ge 2) { $pinned = $true; break }
  }
  Start-Sleep -Milliseconds 500
}
'relay A pinned a key for the hub AND for relay B: ' + $pinned

# --- send across the chain, in force mode -----------------------------------
$send = Start-Process -FilePath (Join-Path $dirS 'UssdApp.exe') `
  -ArgumentList @("--home=$dirS", "--number=$numA", "--relay=127.0.0.1:$portA", `
                  "--send=$numB|$canary", '--watch=60') `
  -WorkingDirectory $dirS -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outS -RedirectStandardError (Join-Path $dirS 'send_err.txt')
$arrived = $false
$ready = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR).IndexOf($canary) -ge 0) { $arrived = $true; break }
  Start-Sleep -Milliseconds 400
}
'chat crossed A -> hub -> B with onion forced: ' + $arrived

# --- and back: the return path is where an asymmetric implementation shows ---
# The watcher has to be stopped first. It holds bob's number on the relay, and a
# second connection registering the same number token kicks the first off - the
# relay is doing its job, but a reply sent into a connection being closed cannot
# report its own result.
try { if (-not $recv.HasExited) { $recv.Kill() } } catch { }
Start-Sleep -Seconds 2
$sendBack = Start-Process -FilePath (Join-Path $dirR 'UssdApp.exe') `
  -ArgumentList @("--home=$dirR", "--number=$numB", "--relay=127.0.0.1:$portB", `
                  "--send=$numA|$back", '--linger=30') `
  -WorkingDirectory $dirR -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $dirR 'sendback_out.txt') `
  -RedirectStandardError (Join-Path $dirR 'sendback_err.txt')
$backOk = $false
$ready = (Get-Date).AddSeconds(50)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outS).IndexOf($back) -ge 0) { $backOk = $true; break }
  Start-Sleep -Milliseconds 400
}
'reply crossed B -> hub -> A with onion forced: ' + $backOk

Start-Sleep -Seconds 3
foreach ($p in @($nodeA, $nodeB, $nodeM)) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
Start-Sleep -Seconds 1

$ta = Read-Text $outA; $tb = Read-Text $outB; $tm = Read-Text $outM
$tr = Read-Text $outR; $ts = Read-Text $outS
$canaryPrints = ([regex]::Matches($tr, 'INBOUND chat from #' + $numA + ': ' + [regex]::Escape($canary))).Count
$backPrints = ([regex]::Matches($ts, 'INBOUND chat from #' + $numB + ': ' + [regex]::Escape($back))).Count
# Computed outside the hashtable: in an expression, "PairLines $tm -eq 0" binds
# -eq and 0 as further arguments to the function, so the check would never have
# compared against anything.
$hubPairs = PairLines $tm
$hubLineCount = @($tm -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }).Count

$tsb = Read-Text (Join-Path $dirR 'sendback_out.txt')
$checks = @()
$checks += @{ n = 'three relay processes came up, leaves dialled the hub'; ok = $linked; d = '' }
$checks += @{ n = 'receiver took its slot on B'; ok = $regB; d = '' }
$checks += @{ n = 'DIRECTORY MERGE two hops away: A lists a peer behind the hub'; ok = $merge; d = '' }
$checks += @{ n = 'relay keys arrived by gossip, not just by link'; ok = $pinned; d = '' }
$checks += @{ n = 'the sender was not refused (force mode found a route)'; ok = (-not ($ta -match 'Refused to forward')); d = '' }
$checks += @{ n = 'chat reached the far endpoint through the hub'; ok = $arrived; d = '' }
$checks += @{ n = 'printed exactly once (no duplicate delivery)'; ok = ($canaryPrints -eq 1); d = 'inbound lines=' + $canaryPrints }
$checks += @{ n = 'the reply reached the originator, also layered'; ok = ($backPrints -eq 1); d = 'inbound lines=' + $backPrints }
# Both directions have to be private, and there are now two legitimate ways to
# achieve that: a session key from a live exchange, or the recipient's published
# identity key. Accepting only the first would fail a run that sealed correctly.
# Nothing is asserted about bob's RESULT line: he lingers longer than the reply
# check takes, and the relays are torn down while he is still sitting there, so
# that line is often never written. His reply arriving at alice is checked on its
# own, two lines above, which is the part that actually matters.
$sealedFwd = ($ts -match 'sealedSession=locked') -or ($ts -match "sealed to #$numB's published key")
$sealedBack = ($tsb -match 'sealedSession=locked') -or ($tsb -match "sealed to #$numA's published key")
$checks += @{ n = 'both ends sent sealed (by session or by published key)'; ok = ($sealedFwd -and $sealedBack); d = "fwd=$sealedFwd back=$sealedBack" }
# ── the point of the whole script: what the hub could see ────────────────────
$checks += @{ n = 'HUB logged an onion hop it carried'; ok = ($tm -match 'ONION carried hop'); d = '' }
$checks += @{ n = 'HUB never received a message envelope (no XF / no MSG)'; ok = (-not ($tm -match 'MSG\|') -and -not ($tm -match 'XF\|')); d = '' }
$checks += @{ n = 'no single line the hub printed names both ends'; ok = ($hubPairs -eq 0); d = 'pair lines=' + $hubPairs + ' of ' + $hubLineCount }
$checks += @{ n = 'the payload never reached the hub'; ok = (-not ($tm.Contains($canary)) -and -not ($tm.Contains($back))); d = '' }
$checks += @{ n = 'the sender relay built a circuit'; ok = ($ta -match 'ONION built'); d = '' }
$checks += @{ n = 'the target relay ended one'; ok = ($tb -match 'ONION delivered to'); d = '' }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
'--- the hub said (last 14) ---'; ($tm -split "`n" | Select-Object -Last 14)
'--- relay A said (last 8) ---'; ($ta -split "`n" | Select-Object -Last 8)
'--- relay keys pinned by A ---'
if (Test-Path $keysFile) { (Get-Content $keysFile) | ForEach-Object { ($_ -split '\|')[0] } }

Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith($base, 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
try { Stop-Transcript | Out-Null } catch { }
if (-not $allOk) { exit 1 }
exit 0
