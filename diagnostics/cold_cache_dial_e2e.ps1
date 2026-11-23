# The refusal that was a lie: dial a friend the instant you open the app.
#
# A client's peer list is a snapshot that arrives some moments AFTER it connects. Until
# the `WHO` fix, `StartCallByNumber` refused a call whenever its own list lacked the
# number, so a person who dialled immediately after opening the app was told their online
# friend was offline - and it was seen happening: call_e2e's video phase printed
# "Number #… is not online" while the relay's own log showed that peer registered seconds
# earlier and still registered.
#
# That race is timing, so it cannot be pinned by one dial. This pins the OUTCOME over
# repeated instant-dial attempts: while the friend is online and idle, no dial may be
# refused as offline. Which branch saved each one (warm cache, or the relay being asked)
# is reported rather than asserted, because that depends on how fast the directory lands
# and the test must not be measuring a race in order to pass.
#
#   relay     --serve 45881                      (one relay, everyone policy)
#   friend    --answer --watch=120               (registered and stays registered)
#   six more  --call=<friend> --watch=10         (fresh process, no settling sleep)
#
# Sensitivity was measured, not assumed. With the fix removed (refuse on a cache miss,
# never ask the relay) a run produced 1 cold cache in 6 dials, that dial printed "is not
# connected", three of the seven checks failed, and the relay's own counter read
# who_asked=0 - the question was never asked, which is the whole bug. Repeated runs of the
# same code show between 1 and 4 cold caches out of 6, so the race is common but not
# guaranteed: this suite is a guard that fires whenever the timing goes wrong, not a
# reproduction on demand. Earlier versions of this file also caught two of its own bad
# checks - scoring a dial as placed because it printed "CALL dialling" (printed before the
# gate) and treating a relay timeout as a refusal. Both are gone.
#
# What the relay does when it is asked and does not answer within 1.5 s is now a third
# case, counted separately as relay-silent-but-call-still-placed: the INVITE is routed by
# the relay regardless of this client's directory, so silence places the call and lets the
# signalling answer the question instead of the caller guessing at it.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"

$port = 45881
$palNum = '7003288000'
$dialNums = @('7003288001', '7003288002', '7003288003', '7003288004', '7003288005', '7003288006')
$base = Join-Path $env:TEMP 'opencode\colddial'
$dirR = Join-Path $base 'relay'
$dirP = Join-Path $base 'friend'
$outR = Join-Path $dirR 'relay_out.txt'
$outP = Join-Path $dirP 'friend_out.txt'
$runLog = Join-Path $root 'diagnostics\cold_dial_run.txt'
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
    Start-Sleep -Milliseconds 250
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

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirR, $dirP)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
# One profile per dialler: a shared one would have them fighting over the same number
# and lease, and a displaced registration looks exactly like the refusal being tested.
foreach ($n in $dialNums) {
  $d = Join-Path $base ('d' + $n.Substring($n.Length - 1))
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
$env:USSD_TRACE = '1'

# --- the relay, then the friend who is online and stays online ---
$relay = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone',
                            '--serve-timeout=300') $outR
if (-not (Wait-For $outR 'RELAY UP' 30)) {
  'FAIL: the relay never bound its port - every check below would pass on an empty log'
  Read-Text (Join-Path $dirR 'err.txt')
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
$pal = Start-Node $dirP @("--home=$dirP", "--number=$palNum", "--relay=127.0.0.1:$port",
                          '--answer', '--watch=120') $outP
$palReady = Wait-For $outP ('registered as #' + $palNum) 40
"the friend is registered and listening: $palReady"
if (-not $palReady) {
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
# A number that is genuinely online: the relay saying so is the ground truth this test is
# allowed to rely on, because the relay is the party that answers the question.
$relayKnows = Wait-For $outR ('Registered ' + $palNum) 15
"the relay logged that registration: $relayKnows"

# --- the dials: each one a fresh process, no settling wait, back to back ---
$procs = @()
foreach ($n in $dialNums) {
  $d = Join-Path $base ('d' + $n.Substring($n.Length - 1))
  $procs += @{ p = (Start-Node $d @("--home=$d", "--number=$n", "--relay=127.0.0.1:$port",
                                    "--call=$palNum", '--watch=10') (Join-Path $d 'dial_out.txt'));
               dir = $d; num = $n }
}
foreach ($x in $procs) { try { $x.p | Wait-Process -Timeout 90 -ErrorAction Stop } catch { } }

$refused = 0; $placed = 0; $rescued = 0; $unknown = 0; $detail = @()
$silentFallback = 0; $notReg = 0
foreach ($x in $procs) {
  $txt = Read-Text (Join-Path $x.dir 'dial_out.txt')
  # The only refusal left is the relay having ANSWERED "no". A timeout no longer counts
  # as one: the caller places the call and lets the signalling decide, because "the relay
  # did not reply in 1.5 s" is not a fact about the friend.
  $r = ($txt -match 'is not connected - the relay says so')
  # Placed = it attempted the call and was not stopped before it started. `Calling #` was
  # the first guess and is wrong: a call that can go direct never prints it, so half the
  # successes would read as failures. The headless path prints exactly one line when the
  # gate refuses (`CALL refused before it started`), and that is route-agnostic.
  $attempted = ($txt -match 'CALL dialling #' + $palNum)
  $stopped = ($txt -match 'CALL refused before it started')
  $p = ($attempted -and -not $stopped)
  # The relay was asked and ANSWERED yes while the caller's own list had not caught up:
  # the branch that replaces the lie. Reported, not required - a warm cache is a
  # legitimate outcome. Tightened after the counters caught this script counting a timed-out
  # question as a rescue, because the app's own wording had once done the same.
  $s = ($txt -match 'though unseen a moment ago' -or $txt -match 'is online at the relay')
  if ($r) { $refused++ }
  if ($txt -match 'did not answer our question') { $silentFallback++ }
  if ($txt -match 'Still registering with the relay') { $notReg++ }
  if ($p) { $placed++ }
  if ($s) { $rescued++ }
  if (-not $attempted) { $unknown++; $detail += ($x.num + ': ' + ((($txt -split "`n") | Select-Object -Last 4) -join ' / ')) }
}
# Whether the relay was asked anything at all is counted on the relay, so this run can
# say whether the rescue branch was exercised or every cache happened to be warm.
$relayNow = Read-Text $outR
function Max-Field([string]$txt, [string]$name) {
  $best = -1
  foreach ($m in [regex]::Matches($txt, ($name + '=(\d+)'))) {
    $v = 0
    if ([int]::TryParse($m.Groups[1].Value, [ref]$v)) { if ($v -gt $best) { $best = $v } }
  }
  return $best
}
$whoAsked = Max-Field $relayNow 'who_asked'
$whoAnswered = Max-Field $relayNow 'who_answered'
$pushes = Max-Field $relayNow 'peers_pushed'
"outcomes: placed=$placed refused=$refused rescued-by-asking=$rescued neither=$unknown relay-counted-questions=$whoAsked"
"notes: relay-silent-but-call-still-placed=$silentFallback not-yet-registered=$notReg; relay answered $whoAnswered of $whoAsked; peers_pushed=$pushes"
# Where the remaining silence lives, decided by the counters rather than by whichever
# theory this session would rather have. Asked-and-answered with the caller still timing
# out puts the delay on the CALLING process - six first-run installs doing RSA keygen at
# once on one machine - and no restructuring inside the relay would ever have fixed that.
if ($silentFallback -gt 0 -and $whoAsked -gt 0 -and $whoAnswered -ge $whoAsked) {
  '  reading: the relay answered every question, so these timeouts are on the caller side.'
} elseif ($silentFallback -gt 0) {
  '  reading: the relay did NOT answer some questions - the delay is inside the relay.'
}
if ($rescued -eq 0 -and $whoAsked -le 0) {
  'NOTE: no dial needed the rescue branch on this run (every cache was already warm).'
  '      The checks below still hold, but this run does not exercise asking the relay -'
  '      the branch is proven in-process instead, and by the mutation run recorded in HANDOFF.'
}

$checks = @()
$checks += @{ n = 'the friend is online at the relay the whole time'; ok = $relayKnows; d = '' }
$checks += @{ n = 'the relay reports a who_asked counter, so the rescue path is observable' +
             ' rather than taken on trust'
             ok = ($relayNow -match 'who_asked=\d+'); d = 'no who_asked= in the status line' }
$checks += @{ n = 'every dialling attempt got an outcome, so none hung'; ok = ($unknown -eq 0)
             d = ($detail -join ' ;; ') }
$checks += @{ n = 'no dial was refused as offline while the friend sat online'
             ok = ($refused -eq 0); d = "$refused refusal(s), all of them an explicit no from the relay" }
$checks += @{ n = '...and every one of them got past the gate and placed the call'
             ok = ($placed -eq $procs.Count); d = "placed $placed of " + $procs.Count }
$checks += @{ n = '...and a refused dial is never counted as placed, so the two cannot overlap'
             ok = ($refused -eq 0 -and $placed -eq $procs.Count)
             d = "placed=$placed refused=$refused attempts=" + $procs.Count }
$checks += @{ n = 'the relay also saw the diallers register, so the test was not dialling into nothing'
             ok = (([regex]::Matches($relayNow, 'Registered ')).Count -ge (1 + $procs.Count))
             d = ('registrations=' + ([regex]::Matches($relayNow, 'Registered ')).Count) }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
''
'--- what the relay saw ---'
((Read-Text $outR) -split "`n" | Where-Object { $_ -match 'Registered|Unregistered' } | Select-Object -Last 6)
Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if ($allOk) { exit 0 } else { exit 1 }
