# A 1:1 call between two relays - the mesh case, as four real processes.
#
# call_e2e.ps1 puts both installs on ONE relay. That is the easier case, and it is the
# one that was ever tested: "your friend runs their own relay and you run yours" means
# the signalling crosses a federation link and the media does too. So here:
#
#   relay A  --serve (45861, dials B, policy everyone)      caller registers here
#   relay B  --serve (45862)                                friend registers here
#   you      --call=... --relay-media
#   friend   --answer --relay-media
#
# --relay-media is what makes this a test rather than a photo of the loopback interface.
# Without it both processes are on this machine, a direct UDP path exists, and the call
# would "succeed" without a single byte crossing the link. Forcing the relay route means
# the relays' own media_fwd/media_del counters can be asked whether the audio really
# travelled through the mesh - which is the claim, so that is the witness.
#
# What is still NOT proven here, and cannot be on one machine: that two laptops on two
# networks can do this. The counters prove the route, not the physics.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"

$portA = 45861
$portB = 45862
$youNum = '7003286001'
$palNum = '7003286002'
$canary = 'XR-CANARY-' + (Get-Date -Format 'HHmmss')
$base = Join-Path $env:TEMP 'opencode\xrelay'
$dirA = Join-Path $base 'relayA'
$dirB = Join-Path $base 'relayB'
$dirY = Join-Path $base 'you'
$dirP = Join-Path $base 'pal'
$outA = Join-Path $dirA 'relay_out.txt'
$outB = Join-Path $dirB 'relay_out.txt'
$outY = Join-Path $dirY 'you_out.txt'
$outY1 = Join-Path $dirY 'call_out.txt'
$outP = Join-Path $dirP 'pal_out.txt'
$runLog = Join-Path $root 'diagnostics\xrelay_call_run.txt'
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
function Kill-Leftovers([string]$base) {
  try {
    foreach ($c in (Get-CimInstance Win32_Process -Filter "Name='UssdApp.exe' OR Name='UssdAgent.exe'" -ErrorAction SilentlyContinue)) {
      if ($c.CommandLine -and $c.CommandLine.Contains($base)) {
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
function Get-Line([string]$txt, [string]$start) {
  foreach ($l in ($txt -split "`n")) { if ($l.Trim().StartsWith($start)) { return $l.Trim() } }
  return '<no ' + $start + ' line>'
}
function SafetyOf([string]$file) {
  # Twelve groups with spaces in them, so take the rest of the line: a \S+ capture
  # would compare four digits and declare a safety number verified.
  foreach ($l in ((Read-Text $file) -split "`n")) {
    if ($l -match 'safety=(.+)$') {
      $v = $Matches[1].Trim()
      if ($v -ne 'none' -and $v.Length -gt 3) { return $v }
    }
  }
  return ''
}
function Tx([string]$txt) { if ($txt -match 'tx_frames=(\d+)') { return [int]$Matches[1] } return -1 }
function Rx([string]$txt) { if ($txt -match 'rx_frames=(\d+)') { return [int]$Matches[1] } return -1 }
# The biggest counter seen in any status beat. The relay prints the same line every
# 10 s, so the newest one is the one that has the call's bytes in it.
function Max-Field([string]$txt, [string]$name) {
  $best = -1
  foreach ($m in [regex]::Matches($txt, ($name + '=(\d+)'))) {
    $v = 0
    if ([int]::TryParse($m.Groups[1].Value, [ref]$v)) { if ($v -gt $best) { $best = $v } }
  }
  return $best
}

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirA, $dirB, $dirY, $dirP)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
$env:USSD_TRACE = '1'

# --- two relays, linked ------------------------------------------------------
$ra = Start-Node $dirA @('--serve', "--port=$portA", "--home=$dirA", '--relay-policy=everyone',
                         "--relay-peers=127.0.0.1:$portB", '--serve-timeout=240') $outA
$rb = Start-Node $dirB @('--serve', "--port=$portB", "--home=$dirB", '--relay-policy=everyone',
                         '--serve-timeout=240') $outB
$upA = Wait-For $outA 'RELAY UP' 30
$upB = Wait-For $outB 'RELAY UP' 30
if (-not ($upA -and $upB)) {
  'FAIL: a relay never bound its port - every check below would pass on an empty log'
  Read-Text (Join-Path $dirA 'err.txt')
  Read-Text (Join-Path $dirB 'err.txt')
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
$linked = Wait-For $outA 'Link up' 30
$linkedBack = Wait-For $outB 'Link up' 30
"the two relay processes linked: $linked / $linkedBack"

# --- the friend, listening on relay B ---------------------------------------
# Its window is longer than the caller's on purpose: the answerer prints its report
# when its own watch ends, and killing it early throws away the half that matters.
$p1 = Start-Node $dirP @("--home=$dirP", "--number=$palNum", "--relay=127.0.0.1:$portB",
                         '--answer', '--relay-media', '--watch=80') $outP
$palReady = Wait-For $outP ('registered as #' + $palNum) 40
"friend registered on relay B: $palReady"

# Relay A has to have learned about a number it has never seen. That is the directory
# merge, and without it the caller cannot even look the friend up.
$merged = Wait-For $outA 'remote_peers=[1-9]' 40
"relay A knows a peer that lives on relay B: $merged"

# --- the text first, because that is what people try first ------------------
$y0 = Start-Node $dirY @("--home=$dirY", "--number=$youNum", "--relay=127.0.0.1:$portA",
                         "--send=$palNum|$canary", '--watch=12') $outY
Wait-For $outP ('INBOUND chat from #' + $youNum) 40 | Out-Null
$textCrossed = (Read-Text $outP).IndexOf($canary) -ge 0
"chat crossed the link: $textCrossed"
# Let the sender's own process finish before the call starts: both register the same
# number, and a second connection displaces the first. Dialling while the old session is
# still on the wire would route the peer's ACCEPT to a socket that is about to close -
# which looks exactly like a cross-relay call failing.
$end = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $end -and -not $y0.HasExited) { Start-Sleep -Milliseconds 400 }

# --- and the call, with the media forced onto the relay route ---------------
$y1 = Start-Node $dirY @("--home=$dirY", "--number=$youNum", "--relay=127.0.0.1:$portA",
                         "--call=$palNum", '--relay-media', '--watch=40') $outY1
$youReported = Wait-For $outY1 'CALL RESULT=' 70
Start-Sleep -Seconds 2
$palReported = Wait-For $outP 'CALL RESULT=' 60
$youTxt = Read-Text $outY1
$palTxt = Read-Text $outP
if (-not $palReported) { 'friend side never reported the call; tail:'; ($palTxt -split "`n" | Select-Object -Last 10) }

# Give the relays one more status beat after the call, so the counters written during
# it are actually in the log we read.
Start-Sleep -Seconds 12
$txtA = Read-Text $outA
$txtB = Read-Text $outB

$fwdA = Max-Field $txtA 'media_fwd'
$fwdB = Max-Field $txtB 'media_fwd'
$delA = Max-Field $txtA 'media_del'
$delB = Max-Field $txtB 'media_del'
"counters  relayA fwd=$fwdA del=$delA   relayB fwd=$fwdB del=$delB"

$safeY = SafetyOf $outY1
$safeP = SafetyOf $outP

$checks = @()
$checks += @{ n = 'two relay processes negotiated a link'; ok = ($linked -and $linkedBack); d = '' }
$checks += @{ n = 'the friend registered on their own relay'; ok = $palReady; d = '' }
$checks += @{ n = 'your relay learned the peer lives on another one'; ok = $merged; d = '' }
$checks += @{ n = 'a chat message crossed the link'; ok = $textCrossed; d = '' }
$checks += @{ n = 'VOICE across two relays: connected, encrypted AND verified'
             ok = ($youTxt -match 'CALL RESULT=connected-encrypted-verified'); d = (Get-Line $youTxt 'CALL RESULT') }
$checks += @{ n = '...and the far side agrees it was verified'
             ok = ($palTxt -match 'CALL RESULT=connected-encrypted-verified'); d = (Get-Line $palTxt 'CALL RESULT') }
$checks += @{ n = '...and both were told the media is relay-routed by request'
             ok = (($youTxt -match 'routed through the relay by request') -and ($palTxt -match 'routed through the relay by request'))
             d = ('you=' + [bool]($youTxt -match 'routed through the relay') + ' pal=' + [bool]($palTxt -match 'routed through the relay')) }
# The route the app names must agree with the counters on the relays. On one machine a
# call can look completely successful while its media never left the loopback, so this is
# the assertion that stops "relayed" from being an assumption: the endpoint itself has to
# say relay, in its own words, and mention an address it never announced as a candidate.
$rtY = ''; if ($youTxt -match 'route=(\S+)') { $rtY = $Matches[1] }
$rtP = ''; if ($palTxt -match 'route=(\S+)') { $rtP = $Matches[1] }
$checks += @{ n = '...and each side names its own route as the relay, not a path it did not use'
             ok = ($rtY -eq 'relay' -and $rtP -eq 'relay') -and
                  ($youTxt -match 'media route: carried by the relay')
             d = ('you=' + $rtY + ' pal=' + $rtP) }
# The receipt has to cross TWO relays to mean anything, and on the relayed path a frame's
# UDP source is the relay rather than the peer - so this is exactly where an address-based
# claim is weakest and a keyed one is the only real evidence. If a relay were dropping our
# audio while faithfully counting the bytes it accepted, the peer's receipt would say zero
# and this would read one-way rather than proved.
$prY = ''; if ($youTxt -match 'pair=(\S+)') { $prY = $Matches[1] }
$prP = ''; if ($palTxt -match 'pair=(\S+)') { $prP = $Matches[1] }
$checks += @{ n = '...and each side holds the peer-signed receipt that its audio arrived, across both relays'
             ok = ($prY -eq 'proved' -and $prP -eq 'proved')
             d = ('you=' + $prY + ' pal=' + $prP) }
$checks += @{ n = '...and the same safety number on both machines'
             ok = ($safeY.Length -gt 20 -and $safeY -eq $safeP); d = "you='$safeY' pal='$safeP'" }
$checks += @{ n = 'your frames went out and theirs came back'
             ok = ((Tx $youTxt) -gt 0 -and (Rx $youTxt) -gt 0); d = "tx=$(Tx $youTxt) rx=$(Rx $youTxt)" }
$checks += @{ n = 'their frames went out and yours came back'
             ok = ((Tx $palTxt) -gt 0 -and (Rx $palTxt) -gt 0); d = "tx=$(Tx $palTxt) rx=$(Rx $palTxt)" }
# The point of the whole script: the relays, not the endpoints, say they carried it.
$checks += @{ n = 'RELAY A counted media frames it forwarded toward the link'
             ok = ($fwdA -gt 0); d = "media_fwd=$fwdA" }
$checks += @{ n = 'RELAY B counted media frames it delivered to its own client'
             ok = ($delB -gt 0); d = "media_del=$delB" }
$checks += @{ n = '...and the same in reverse, so the path is not one-way'
             ok = ($fwdB -gt 0 -and $delA -gt 0); d = "B fwd=$fwdB, A del=$delA" }
$checks += @{ n = 'neither relay logged the chat canary in clear'
             ok = (($txtA.IndexOf($canary) -lt 0) -and ($txtB.IndexOf($canary) -lt 0)); d = '' }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
''
'--- what relay A said ---'
(($txtA -split "`n") | Where-Object { $_ -match 'Link up|Registered|RELAY STATUS|media' } | Select-Object -Last 6)
'--- your side ---'
(($youTxt -split "`n") | Select-Object -Last 8)
Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if ($allOk) { exit 0 } else { exit 1 }
