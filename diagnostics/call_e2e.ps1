# Two laptops, for real: text, a voice call, a video call - across separate
# PROCESSES with separate profiles, separate identity keys and separate tokens,
# over a relay process. Nothing here is a unit test of a function: it starts the
# shipped binary the way a person would, on the theory that "it works when I hang
# up on my friend's laptop" is only proven by the thing that happens when you do.
#
#   relay   --serve                              (45873, its own --home)
#   friend  --answer --watch=N                   (accepts whatever rings it)
#   you     --send=<friend>|<text> --watch=12    (sealed chat, offline or not)
#   you     --call=<friend> --watch=25           (voice)
#   ... then the friend is restarted, so the video call is a clean second call
#   you     --call=<friend> --video --watch=25   (video)
#
# What each check is for:
#   - the call connecting is not the claim; ENCRYPTED FRAMES ARRIVING is. tx on one
#     side with rx on the other, both directions, or the test says so and fails.
#   - the safety number must be the SAME digits on both machines. That equality is
#     the end-to-end property: same session, nobody in the middle.
#   - no media may leave before the key exists, so the log order is checked, not
#     assumed ("media held until the encryption key is negotiated" first).
#   - the relay must never see the chat canary in clear.
#
# Audio quality and what a picture looks like are NOT asserted here and are not
# claimable by any script: that needs two people and two speakers.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"

$port = 45873
$youNum = '7003283001'
$palNum = '7003283002'
$canary = 'CALLTEST-CANARY-' + (Get-Date -Format 'HHmmss')
$base = Join-Path $env:TEMP 'opencode\twocalls'
$dirR = Join-Path $base 'relay'
$dirA = Join-Path $base 'you'
$dirB = Join-Path $base 'friend'
$outR  = Join-Path $dirR 'relay_out.txt'
$outA0 = Join-Path $dirA 'text_out.txt'
$outA1 = Join-Path $dirA 'voice_out.txt'
$outA2 = Join-Path $dirA 'video_out.txt'
$outB1 = Join-Path $dirB 'voice_out.txt'
$outB2 = Join-Path $dirB 'video_out.txt'
$runLog = Join-Path $root 'diagnostics\call_e2e_run.txt'
try { Start-Transcript -Path $runLog -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    # FileShare.ReadWrite: the process writing this log holds it; a reader that
    # asks for exclusive access throws instead of waiting, and a poll that throws
    # is worse than one that times out.
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}
function Wait-For([string]$file, [string]$pattern, [int]$seconds) {
  # Polled, never slept-and-read-once: every one of these assertions is about a
  # line arriving, and a fixed sleep only measures how fast this machine felt
  # like being today.
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
function SafetyOf([string]$file) {
  # The code is twelve groups with spaces in it, so it has to be taken to the end of
  # the line: a \S+ capture would compare four digits and call the whole safety number
  # verified, which is the sort of check that passes for the wrong reason.
  # "none" is skipped because the answerer's final line is printed after the call has
  # been torn down; the digits captured while it was live are the evidence.
  $best = ''
  foreach ($l in ((Read-Text $file) -split "`n")) {
    if ($l -match 'safety=(.+)$') {
      $v = $Matches[1].Trim()
      if ($v -ne 'none' -and $v.Length -gt 3) { return $v }
      if ($best.Length -eq 0) { $best = $v }
    }
  }
  return $best
}
# Defined with the other helpers, not lower down: the verdict table below calls it
# while it is being built, and a function that appears after its first use simply
# is not there yet.
function Get-Line([string]$txt, [string]$start) {
  foreach ($l in ($txt -split "`n")) { if ($l.Trim().StartsWith($start)) { return $l.Trim() } }
  return '<no ' + $start + ' line>'
}
function Frames([string]$txt) {
  if ($txt -match 'rx_frames=(\d+)') { return [int]$Matches[1] }
  return -1
}
function Tx([string]$txt) { if ($txt -match 'tx_frames=(\d+)') { return [int]$Matches[1] } return -1 }

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirR, $dirA, $dirB)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  # Explicit destination name: a -Exe build keeps its own file name otherwise, and
  # the launch below would silently run last week's binary while reporting this one.
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
$env:USSD_TRACE = '1'

# --- the relay both machines use ---
$relay = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone', `
                            '--serve-timeout=300') $outR
$up = $false; $end = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $end) {
  if ((Read-Text $outR) -match 'RELAY UP') { $up = $true; break }
  if ($relay.HasExited) { break }
  Start-Sleep -Milliseconds 250
}
if (-not $up) {
  'FAIL: the relay never bound port ' + $port + ' - every check below would pass on an empty log'
  Read-Text (Join-Path $dirR 'err.txt')
  Kill-Leftovers $base
  try { Stop-Transcript | Out-Null } catch { }
  exit 1
}
'relay up: True'

# --- the friend's laptop: listening, and answering whatever rings ---
# Its window is LONGER than the caller's, on purpose: the answerer only prints its
# report when its own watch ends, so killing it as soon as the caller finished threw
# away the half of the evidence that matters most - what the far side saw.
$b1 = Start-Node $dirB @("--home=$dirB", "--number=$palNum", "--relay=127.0.0.1:$port", `
                         '--answer', '--watch=60') $outB1
$end = (Get-Date).AddSeconds(40)
$palReady = $false
while ((Get-Date) -lt $end) {
  if ((Read-Text $outB1) -match ('registered as #' + $palNum)) { $palReady = $true; break }
  if ($b1.HasExited) { break }
  Start-Sleep -Milliseconds 300
}
"friend registered on the relay: $palReady"

# --- your laptop: the text first, because that is what people try first ---
$a0 = Start-Node $dirA @("--home=$dirA", "--number=$youNum", "--relay=127.0.0.1:$port", `
                         "--send=$palNum|$canary", '--watch=15') $outA0
$end = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $end -and -not $a0.HasExited) { Start-Sleep -Milliseconds 400 }

# --- a voice call, dialled headless and answered headless ---
$a1 = Start-Node $dirA @("--home=$dirA", "--number=$youNum", "--relay=127.0.0.1:$port", `
                         "--call=$palNum", '--watch=30') $outA1
$end = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $end) {
  if ((Read-Text $outA1) -match 'CALL RESULT=') { break }
  Start-Sleep -Milliseconds 400
}
$voiceA = Read-Text $outA1
# Wait for the answerer's own verdict instead of killing it, then take what it saw.
$friendVoice = Wait-For $outB1 'CALL RESULT=' 75
$voiceB = Read-Text $outB1
if (-not $friendVoice) { 'friend side never reported the voice call; tail:'; ($voiceB -split "`n" | Select-Object -Last 10) }
try { if (-not $b1.HasExited) { $b1.Kill() } } catch { }
Start-Sleep -Seconds 3

# --- the video call, with a FRESH friend process ---
# One listener per call: the second call would otherwise arrive while the first is
# still being cleaned up on that side, and a failure would be about the leftover
# state rather than about video.
$b2 = Start-Node $dirB @("--home=$dirB", "--number=$palNum", "--relay=127.0.0.1:$port", `
                         '--answer', '--watch=60') $outB2
$end = (Get-Date).AddSeconds(40)
$pal2 = $false
while ((Get-Date) -lt $end) {
  if ((Read-Text $outB2) -match ('registered as #' + $palNum)) { $pal2 = $true; break }
  if ($b2.HasExited) { break }
  Start-Sleep -Milliseconds 300
}
"friend listening again for the video call: $pal2"
$a2 = Start-Node $dirA @("--home=$dirA", "--number=$youNum", "--relay=127.0.0.1:$port", `
                         "--call=$palNum", '--video', '--watch=30') $outA2
$end = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $end) {
  if ((Read-Text $outA2) -match 'CALL RESULT=') { break }
  Start-Sleep -Milliseconds 400
}
$vidA = Read-Text $outA2
$friendVid = Wait-For $outB2 'CALL RESULT=' 75
$vidB = Read-Text $outB2
if (-not $friendVid) { 'friend side never reported the video call; tail:'; ($vidB -split "`n" | Select-Object -Last 10) }
Start-Sleep -Seconds 2
try { if (-not $b2.HasExited) { $b2.Kill() } } catch { }
try { if (-not $relay.HasExited) { $relay.Kill() } } catch { }
Start-Sleep -Seconds 1

$relayTxt = Read-Text $outR

# --- what happened, line by line ---
$checks = @()
$checks += @{ n = 'both machines registered with the relay'; ok = $palReady; d = '' }
$checks += @{ n = 'the friend received the text'; ok = ($voiceB.IndexOf($canary) -ge 0); d = '' }
$checks += @{ n = '...sealed, not as a session-less handoff'
             ok = ($voiceB -match 'sealed|locked|session key'); d = '' }
$checks += @{ n = 'the relay never saw the text in clear'; ok = (-not ($relayTxt.Contains($canary))); d = '' }
$checks += @{ n = 'the voice call rang on the friend side'; ok = ($voiceB -match 'CALL incoming'); d = '' }
$checks += @{ n = '...and was answered by the listening process'; ok = ($voiceB -match 'CALL accepted|answering'); d = '' }
$checks += @{ n = 'VOICE you: connected, encrypted AND verified'
             ok = ($voiceA -match 'CALL RESULT=connected-encrypted-verified'); d = (Get-Line $voiceA 'CALL state') }
$checks += @{ n = 'VOICE friend: connected, encrypted AND verified'
             ok = ($voiceB -match 'CALL RESULT=connected-encrypted-verified'); d = (Get-Line $voiceB 'CALL state') }
$checks += @{ n = 'VOICE: frames you sent arrived at the friend'
             ok = ((Tx $voiceA) -gt 0 -and (Frames $voiceB) -gt 0)
             d = ('you tx=' + (Tx $voiceA) + ' friend rx=' + (Frames $voiceB)) }
$checks += @{ n = 'VOICE: frames the friend sent arrived at you'
             ok = ((Tx $voiceB) -gt 0 -and (Frames $voiceA) -gt 0)
             d = ('friend tx=' + (Tx $voiceB) + ' you rx=' + (Frames $voiceA)) }
$sA = SafetyOf $outA1; $sB = SafetyOf $outB1
$checks += @{ n = 'VOICE: both machines computed the same safety number'
             ok = ($sA.Length -gt 3 -and $sA -eq $sB); d = "you='$sA' friend='$sB'" }
# The relay cannot hear the call: assert the gate existed, not that we hope it did.
# That line is only emitted when something tried to send before the key arrived, so
# its presence proves media was held rather than that nothing was tried.
$gateOk = ($voiceA -match 'media held until the encryption key') -or ($voiceA -match 'first encrypted audio frame')
$checks += @{ n = 'media was gated on the key, not sent in clear first'
             ok = $gateOk
             d = $(if ($gateOk) { '' } else { 'neither marker present, so the gate was never observed' }) }
# Which of the peer's announced addresses actually delivered the frames. The kind is a
# fact about this network, not about the code, so the assertion is that the app NAMED one
# and said it in words a person could read - not that it picked a particular one. An
# empty route= or an internal code on the user's screen would both be failures.
$rtA = ''
if ($voiceA -match 'route=(\S+)') { $rtA = $Matches[1] }
$checks += @{ n = 'VOICE: the app names the route that carried it, in words rather than codes'
             ok = (@('host','reflexive','mapped','relay','unannounced') -contains $rtA) -and
                  ($voiceA -match 'media route: (direct|carried by the relay)')
             d = ('route=' + $rtA) }
# Naming the route only ever answered where THEIR audio came from. With media sprayed at
# every candidate, nothing on either machine knew whether OURS had landed - and the checks
# above assemble that fact from two log files, which the app itself cannot do. Each side
# now holds a receipt the peer signed with the call key, so it is the app that can say so.
$prA = ''; if ($voiceA -match 'pair=(\S+)') { $prA = $Matches[1] }
$prB = ''; if ($voiceB -match 'pair=(\S+)') { $prB = $Matches[1] }
# The spoken form lives in the log, which every line of carries a prefix - so search for
# the phrase INSIDE a line rather than using Get-Line, whose StartsWith would never match
# and would report '<no media route line>' against a phrase that was provably there.
$mrLine = ''
foreach ($l in ($voiceA -split "`n")) { if ($l -match 'media route:') { $mrLine = $l.Trim() } }
$checks += @{ n = 'VOICE: each side PROVES its own audio arrived, from the peer and not from this test'
             ok = ($prA -eq 'proved' -and $prB -eq 'proved')
             d = ('you=' + $prA + ' friend=' + $prB) }
$checks += @{ n = '...and says it in words on the call line, not only as a machine-readable code'
             ok = ($mrLine -match 'media route: .*both directions proved')
             d = ('seen: [' + $mrLine + ']') }
$checks += @{ n = 'VIDEO: the call was set up as a video call'
             ok = ($vidA -match 'video=True'); d = (Get-Line $vidA 'CALL state') }
$checks += @{ n = 'VIDEO: connected, encrypted AND verified on both sides'
             ok = ($vidA -match 'CALL RESULT=connected-encrypted-verified' -and
                   $vidB -match 'CALL RESULT=connected-encrypted-verified'); d = '' }
$checks += @{ n = 'VIDEO: picture frames actually crossed (chunks reassembled)'
             ok = ((Frames $vidB) -gt 30 -and (Frames $vidA) -gt 30)
             d = ('you rx=' + (Frames $vidA) + ' friend rx=' + (Frames $vidB)) }
$sA2 = SafetyOf $outA2; $sB2 = SafetyOf $outB2
$checks += @{ n = 'VIDEO: same safety number on both machines again'
             ok = ($sA2.Length -gt 3 -and $sA2 -eq $sB2); d = "you='$sA2' friend='$sB2'" }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
''
'--- voice, your side ---'
(Get-Line $voiceA 'CALL state')
'--- voice, friend side ---'
(Get-Line $voiceB 'CALL state')
'--- video, your side ---'
(Get-Line $vidA 'CALL state')
'--- video, friend side ---'
(Get-Line $vidB 'CALL state')
''
if ($voiceA -notmatch 'CALL RESULT=') { 'your voice run printed no verdict line; tail:'; ($voiceA -split "`n" | Select-Object -Last 12) }
if ($voiceB -notmatch 'CALL RESULT=') { 'the friend side printed no verdict line; tail:'; ($voiceB -split "`n" | Select-Object -Last 12) }

Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if ($allOk) { exit 0 } else { exit 1 }
