# "My mate downloads the app - can we talk by number?" Proven end to end.
#
# This is the question the whole project exists to answer, and until now no suite
# answered it as a sequence a real pair would live through. Every other call/chat test
# starts from two profiles that already know their numbers and already have each other
# in some form. Here the mate's folder contains ONE FILE - the exe they downloaded -
# and the only thing they are given is the line this relay printed.
#
#   relay     my PC hosting a relay, prints SEED LINE           (my machine, 45891)
#   me        my own profile, my own 700 number
#   mate      a PRISTINE profile: no config, no identity key, no number, no peers.
#             Started with --bootstrap and nothing but the pasted seed line.
#
# Four phases, because a headless watcher exits when its first message arrives - and
# that is also just what happens when two people open and close the app:
#
#   1  they open it and get a number of their own (nothing handed to them)
#   2  they message ME first, a stranger, by my number
#   3  I message THEM while their app is shut, and it is there when they reopen it
#   4  a call to the number they invented, answered, verified, media both ways
#
# What this cannot do is the one thing it would need to be perfect: put the two profiles
# on two real machines on two networks. It is eight processes on one machine, so the
# addresses are LAN ones and the physics of two NATs is still unproven. Everything else
# - the minting, the pinning, the sealing to a key never exchanged, the store-and-forward,
# the authenticated call - is the same code path a mate would run.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"

$port = 45891
$myNum = '7003291001'
$base = Join-Path $env:TEMP 'opencode\mateapp'
$dirR = Join-Path $base 'relay'
$dirM = Join-Path $base 'me'
$dirF = Join-Path $base 'mate'
$outR = Join-Path $dirR 'relay_out.txt'
$outM = Join-Path $dirM 'me_out.txt'
$runLog = Join-Path $root 'diagnostics\mateapp_run.txt'
try { Start-Transcript -Path $runLog -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}
function Wait-For([string]$file, [string]$pattern, [int]$seconds) {
  $end = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $end) {
    if ((Read-Text $file) -match $pattern) { return $true }
    Start-Sleep -Milliseconds 300
  }
  return ((Read-Text $file) -match $pattern)
}
function Kill-Leftovers([string]$b) {
  try {
    foreach ($c in (Get-CimInstance Win32_Process -Filter "Name='UssdApp.exe' OR Name='UssdAgent.exe'" -ErrorAction SilentlyContinue)) {
      if ($c.CommandLine -and $c.CommandLine.Contains($b)) {
        try { Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue } catch { }
      }
    }
  } catch { }
}
function Start-Node([string]$dir, [string[]]$argv, [string]$out) {
  Start-Process -FilePath (Join-Path $dir 'UssdApp.exe') -ArgumentList $argv `
    -WorkingDirectory $dir -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $out -RedirectStandardError (Join-Path $dir 'err.txt')
}
function Last-Line([string]$file, [string]$pattern) {
  $hit = ''
  foreach ($l in ((Read-Text $file) -split "`n")) { if ($l -match $pattern) { $hit = $l.Trim() } }
  return $hit
}
# Line by line, and skipping "none": the safety number is twelve groups with spaces in
# it, so a whole-file match anchored at end-of-line would only work if it happened to be
# the last line printed - and the last line is the CALL RESULT, which has no digits in
# it. A test that read an empty string from both sides and called them equal would be the
# worst kind of pass, so nothing shorter than a full twelve groups is accepted here.
function Safety-Of([string]$file) {
  $best = ''
  foreach ($l in ((Read-Text $file) -split "`n")) {
    if ($l -match 'safety=(.+)$') {
      $v = $Matches[1].Trim()
      if ($v -ne 'none' -and $v.Length -gt 20) { return $v }
    }
  }
  return $best
}

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }

# --- the two folders: mine is a normal profile, theirs is a download ----------
New-Item -ItemType Directory -Force -Path $dirR, $dirM, $dirF | Out-Null
Copy-Item $appExe -Destination (Join-Path $dirR 'UssdApp.exe') -Force
Copy-Item $appExe -Destination (Join-Path $dirM 'UssdApp.exe') -Force
$relay = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone',
                            '--serve-timeout=420') $outR
if (-not (Wait-For $outR 'RELAY UP' 30)) {
  'FAIL: my relay never bound port ' + $port + ' - everything below would pass on an empty log'
  Read-Text (Join-Path $dirR 'err.txt')
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
Wait-For $outR 'SEED LINE' 12 | Out-Null
# The line I would text them. Parsed from the relay's own output, never retyped, so a
# stale fingerprint cannot pass and a wrong address cannot quietly be what the test used.
$seedAddr = ''; $seedFp = ''
foreach ($l in ((Read-Text $outR) -split "`n")) {
  if ($l -match 'SEED LINE (\S+)\|(\S+)\|') { $seedAddr = $Matches[1]; $seedFp = $Matches[2]; break }
}
"the line my mate would be sent: $seedAddr | $seedFp"
if (-not $seedFp) { Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1 }

# The mate's folder is EXACTLY what a download is: the program and the one pasted line.
# Nothing else. No config, no identity key, no number, no peer list, no relay address.
Copy-Item $appExe -Destination (Join-Path $dirF 'UssdApp.exe') -Force
Set-Content -Path (Join-Path $dirF 'relays.seed') -Value "# from a friend`n$seedAddr|$seedFp|their relay" -Encoding ascii
$before = @((Get-ChildItem $dirF -Force | ForEach-Object { $_.Name }) | Sort-Object) -join ','
"the mate's folder before they run it: $before"

# me: my own profile, my own number, on my own relay
$me = Start-Node $dirM @("--home=$dirM", "--number=$myNum", "--relay=$seedAddr",
                         '--watch=240') $outM
$meReady = Wait-For $outM ('registered as #' + $myNum) 60
"my app is up as #" + $myNum + ": $meReady"

$checks = @()
$checks += @{ n = 'my mate received only the program and one line to paste'
             ok = ($before -eq 'relays.seed,UssdApp.exe'); d = 'folder held: ' + $before }
$checks += @{ n = 'and my own app is registered on my relay'; ok = $meReady; d = '' }

# --- phase 1: they open it, and get a number of their own -------------------
$f1 = Join-Path $dirF 'p1_out.txt'
$p1 = Start-Node $dirF @("--home=$dirF", '--bootstrap', '--watch=25') $f1
$up1 = Wait-For $f1 'HEADLESS number=' 60
Start-Sleep -Seconds 3
$head1 = Last-Line $f1 'HEADLESS number='
$mateNum = ''
if ($head1 -match 'HEADLESS number=(\S+)') { $mateNum = $Matches[1] }
"phase 1 - their app came up as #" + $mateNum
$trust1 = ''; if ($head1 -match 'relay_trust=(\S+)') { $trust1 = $Matches[1] }
$checks += @{ n = 'phase 1: they connected with nothing but the pasted line'
             ok = ($up1 -and ($head1 -match 'connected=True')); d = $head1 }
$checks += @{ n = '...and minted an app number themselves, in the shareable form'
             ok = ($mateNum -match '^700\d{7}$'); d = 'number=' + $mateNum }
$checks += @{ n = '...and it is their OWN number, not mine or one handed to them'
             ok = ($mateNum -ne $myNum -and $mateNum.Length -eq 10); d = 'number=' + $mateNum }
$checks += @{ n = '...and they pinned my relay key from the seed rather than trusting the address'
             ok = ($trust1 -match '^verified-(new|known)$'); d = 'relay_trust=' + $trust1 }
# Their identity key lives in their profile and nowhere else - that is what makes the
# number theirs, and what a relay cannot forge.
$idLine = Last-Line $f1 'identity key'
$checks += @{ n = '...and they hold their own identity key, minted on their machine'
             ok = ($idLine -match 'identity key [0-9A-F]{8}-[0-9A-F]{8}'); d = $idLine }
try { if (-not $p1.HasExited) { $p1.Kill() } } catch { }
Start-Sleep -Seconds 2

# --- phase 2: they message me first, a stranger they have never corresponded with ---
$canaryFromMate = 'MATE-TO-ME-' + (Get-Date -Format 'HHmmss')
$f2 = Join-Path $dirF 'p2_out.txt'
$p2 = Start-Node $dirF @("--home=$dirF", '--bootstrap', "--send=$myNum|$canaryFromMate", '--watch=45') $f2
$gotMine = Wait-For $outM ([regex]::Escape($canaryFromMate)) 60
$send2 = Last-Line $f2 'RESULT sent='
$checks += @{ n = 'phase 2: they wrote to my number and I received it'
             ok = $gotMine; d = $(if ($gotMine) { '' } else { ('their send said: ' + $send2) }) }
$checks += @{ n = '...and it arrived as mine, addressed correctly'
             ok = ((Read-Text $outM) -match ('INBOUND chat from #' + $mateNum + ': ' + [regex]::Escape($canaryFromMate)))
             d = Last-Line $outM 'INBOUND chat' }
try { if (-not $p2.HasExited) { $p2.Kill() } } catch { }
Start-Sleep -Seconds 2

# --- phase 3: I write to them while their app is shut ----------------------
# The number they invented is all I have. Their app is closed, their laptop may be
# asleep. This is the store-and-forward claim, made against a stranger's key.
$canaryToMate = 'ME-TO-MATE-' + (Get-Date -Format 'HHmmss')
$f3 = Join-Path $dirM 'p3_out.txt'
$p3 = Start-Node $dirM @("--home=$dirM", "--number=$myNum", "--relay=$seedAddr",
                         "--send=$mateNum|$canaryToMate", '--linger=6') $f3
try { $p3 | Wait-Process -Timeout 70 -ErrorAction SilentlyContinue } catch { }
$res3 = Last-Line (Join-Path $dirM 'p3_out.txt') 'RESULT sent='
$sealedStranger = ((Read-Text (Join-Path $dirM 'p3_out.txt')) -match ("sealed to #" + [regex]::Escape($mateNum) + "'s published key"))
$checks += @{ n = 'phase 3: with their app shut, my message was accepted, not dropped'
             ok = ($res3 -match 'sent=True'); d = $res3 }
$checks += @{ n = '...and it was sealed to a key I never exchanged a session for'
             ok = $sealedStranger
             d = $(if ($sealedStranger) { '' } else { 'no "sealed to published key" line - so it went in clear or not at all' }) }
# The relay must be left holding bytes it cannot read.
$relayHolds = Read-Text $outR
$checks += @{ n = '...and the relay is left holding it without seeing the text'
             ok = ($relayHolds.IndexOf($canaryToMate) -lt 0)
             d = $(if ($relayHolds.IndexOf($canaryToMate) -lt 0) { '' } else { 'the canary appeared in the relay log' }) }
# They reopen the app - the same folder, the same number, no re-configuration.
$f4 = Join-Path $dirF 'p4_out.txt'
$p4 = Start-Node $dirF @("--home=$dirF", '--bootstrap', '--watch=50') $f4
$gotQueued = Wait-For $f4 ([regex]::Escape($canaryToMate)) 70
$checks += @{ n = '...and it is there when they open the app again, unopened by anyone else'
             ok = $gotQueued; d = Last-Line $f4 'INBOUND chat' }
$checks += @{ n = '...and they recognise my number as the sender'
             ok = ((Read-Text $f4) -match ('INBOUND chat from #' + $myNum + ': ' + [regex]::Escape($canaryToMate)))
             d = '' }

# --- phase 4: a call to the number they made up ----------------------------
$mateNumForCall = $mateNum
$f5 = Join-Path $dirF 'p5_out.txt'
$p5 = Start-Node $dirF @("--home=$dirF", '--bootstrap', '--answer', '--watch=90') $f5
Wait-For $f5 ('registered as #' + $mateNumForCall) 60 | Out-Null
$f6 = Join-Path $dirM 'p6_out.txt'
$p6 = Start-Node $dirM @("--home=$dirM", "--number=$myNum", "--relay=$seedAddr",
                         "--call=$mateNumForCall", '--watch=30') $f6
$meReported = Wait-For $f6 'CALL RESULT=' 70
$mateReported = Wait-For $f5 'CALL RESULT=' 70
$callMe = Read-Text $f6
$callMate = Read-Text $f5
$safeMe = Safety-Of $f6
$safeMate = Safety-Of $f5
"phase 4 - my side: " + (Last-Line $f6 'CALL state')
$checks += @{ n = 'phase 4: a call to their invented number connected, encrypted AND verified'
             ok = ($callMe -match 'CALL RESULT=connected-encrypted-verified'); d = (Last-Line $f6 'CALL RESULT') }
$checks += @{ n = '...and they experienced the same call on their side'
             ok = ($callMate -match 'CALL RESULT=connected-encrypted-verified'); d = (Last-Line $f5 'CALL RESULT') }
$checks += @{ n = '...and both screens show the same safety number, so nobody sat between us'
             ok = ($safeMe.Length -gt 20 -and $safeMe -eq $safeMate)
             d = "me='$safeMe' mate='$safeMate'" }
$txMe = -1; $rxMe = -1; $txMate = -1; $rxMate = -1
if ($callMe -match 'tx_frames=(\d+)') { $txMe = [int]$Matches[1] }
if ($callMe -match 'rx_frames=(\d+)') { $rxMe = [int]$Matches[1] }
if ($callMate -match 'tx_frames=(\d+)') { $txMate = [int]$Matches[1] }
if ($callMate -match 'rx_frames=(\d+)') { $rxMate = [int]$Matches[1] }
$checks += @{ n = '...and audio frames went both ways, not one way and a promise'
             ok = ($txMe -gt 0 -and $rxMe -gt 0 -and $txMate -gt 0 -and $rxMate -gt 0)
             d = "me tx=$txMe rx=$rxMe / mate tx=$txMate rx=$rxMate" }

''
'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
''
'their number was #' + $mateNum + ' - minted on their machine from a folder that held only the exe and my line.'
'--- what the relay saw (no plaintext in any of it) ---'
((Read-Text $outR) -split "`n" | Where-Object { $_ -match 'Registered|Unregistered|MAIL|stored|queued|carried' } | Select-Object -Last 8)
Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if ($allOk) { exit 0 } else { exit 1 }
