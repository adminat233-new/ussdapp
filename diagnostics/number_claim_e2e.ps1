# Number-claim defence, across REAL PROCESSES.
#
# The in-process suite proves the relay refuses a wrong token. This proves the
# thing that actually matters to a user: a *second install*, with its own
# identity.key and its own number_token in its own profile folder, pointed at the
# same relay and the same number, cannot take that number over while the owner is
# away - and cannot read what was left for them either.
#
#   relay   --serve                     (45871, its own --home)
#   owner   registers, then leaves      (legit install, real token)
#   sender  mails the absent owner        (so there is something to steal)
#   thief   same number, own profile     (must be refused, must see nothing)
#   owner   returns                      (must get the mail, must be told of attempts)
#   relay   --release-number=<owner>     (the escape hatch, then the thief gets in)
#
# That last step is not a formality: a lockout with no way out would be worse
# than the hole this closes, so the fix is only correct if the release works.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"
$port = 45871
$ownerNum = '7003271001'
$senderNum = '7003271002'
$canary = 'CLAIM-CANARY-' + (Get-Date -Format 'HHmmss')
$base = Join-Path $env:TEMP 'opencode\claim'
$dirR = Join-Path $base 'relay'; $dirO = Join-Path $base 'owner'
$dirS = Join-Path $base 'sender'; $dirT = Join-Path $base 'thief'
$outR = Join-Path $dirR 'relay_out.txt'; $outO1 = Join-Path $dirO 'first_out.txt'
$outO2 = Join-Path $dirO 'back_out.txt'; $outS = Join-Path $dirS 'send_out.txt'
$outT = Join-Path $dirT 'thief_out.txt'; $outT2 = Join-Path $dirT 'thief_after_release.txt'
$outR2 = Join-Path $dirR 'relay2_out.txt'
$runLog = Join-Path $root 'diagnostics\number_claim_run.txt'
try { Start-Transcript -Path $runLog -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}
function Kill-Leftovers([string]$base) {
  # Command line, not process path: a leftover whose exe file was deleted has no
  # resolvable Path, and it is the one still holding the port.
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

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirR, $dirO, $dirS, $dirT)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  # Explicit destination file name, or a build passed in as -Exe keeps its own name
  # and the launch below silently runs whatever old UssdApp.exe is lying around.
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
$env:USSD_TRACE = '1'

# --- the relay ---
$relay = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone', `
                           '--relay-carry-mail', '--serve-timeout=230') $outR
# Gate on it actually binding: with no relay, every check below would "pass" on an
# empty log, which is the failure mode that makes a harness useless.
# PowerShell binds `+` tighter than `-match`, so `A -match 'x' + $n` is
# `(A -match 'x') + $n` - a boolean with a string glued to it, not a search for
# "x$n". Every pattern below that interpolates a number is parenthesised for that
# reason; without it several of these checks would have been quietly meaningless.
$up = $false; $ready = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match 'RELAY UP') { $up = $true; break }
  if ($relay.HasExited) { break }
  Start-Sleep -Milliseconds 250
}
if (-not $up) {
  'FAIL: the relay never came up on port ' + $port
  (Read-Text (Join-Path $dirR 'err.txt'))
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
'relay up: True'

# --- the owner connects once, with their own real token, and leaves ---
# --watch is what selects the headless path: without it the exe starts the GUI,
# which registers perfectly and prints nothing to a redirected handle - so the
# first draft of this line read "the owner never registered" while the relay log
# showed him registering twice. Watch, do not linger: it exits on its own.
$o1 = Start-Node $dirO @("--home=$dirO", "--number=$ownerNum", "--relay=127.0.0.1:$port", '--watch=14') $outO1
$claimed = $false
$ready = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outO1) -match ('registered as #' + $ownerNum)) { $claimed = $true; break }
  if ($o1.HasExited) { break }
  Start-Sleep -Milliseconds 300
}
"the owner registered and claimed the number: $claimed"
$leaseFile = Join-Path $dirR 'number_leases.txt'
$leased = (Test-Path $leaseFile) -and ((Read-Text $leaseFile) -match $ownerNum)
"a lease was written to disk: $leased"
$plainToken = $false
if (Test-Path $leaseFile) {
  # The token is a shared secret; the file must not hand it out to whoever can read
  # a relay folder (which, for a relay in a shared space, is not nobody).
  $cfg = Get-Content (Join-Path $dirO 'ussd_config.json') -Raw -ErrorAction SilentlyContinue
  $tok = ''
  if ($cfg -match '"number_token"\s*:\s*"([^"]+)"') { $tok = $Matches[1] }
  $plainToken = ($tok.Length -gt 0 -and (Read-Text $leaseFile).Contains($tok))
}
"the lease stores the token in the clear: $plainToken   (must be False)"
try { if (-not $o1.HasExited) { $o1.Kill() } } catch { }
# Wait for the relay to notice, rather than assuming two seconds is enough: this
# assertion exists precisely to prove the owner is absent during the attack, so a
# stale "still connected" here would quietly invalidate every check after it.
$ownerGone = $false
$ready = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match ('Unregistered ' + $ownerNum)) { $ownerGone = $true; break }
  Start-Sleep -Milliseconds 300
}
"the owner is off-line: $ownerGone"

# --- somebody leaves the absent owner a message ---
$send = Start-Node $dirS @("--home=$dirS", "--number=$senderNum", "--relay=127.0.0.1:$port", `
                           "--send=$ownerNum|$canary", '--linger=20') $outS
# Polled, not slept-and-read-once. Whether that line has landed six seconds after
# the sender started depends on when the process JIT'd, connected and registered;
# on a busy machine it had not, and the check failed while the relay had in fact
# queued the message. A fixed sleep turns a slow machine into a wrong report.
$queued = $false
$ready = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match ('Queued offline message for ' + $ownerNum)) { $queued = $true; break }
  Start-Sleep -Milliseconds 300
}
"the message was queued for the absent owner: $queued"

# --- the theft attempt: different install, different token, same number ---
$thief = Start-Node $dirT @("--home=$dirT", "--number=$ownerNum", "--relay=127.0.0.1:$port", '--watch=25') $outT
$refused = $false
$ready = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $ready) {
  $t = Read-Text $outT
  if (($t -match 'leased to another install') -or ($t -match 'refused')) { $refused = $true; break }
  if ($thief.HasExited) { break }
  Start-Sleep -Milliseconds 300
}
# The negatives are taken from the whole file after the thief has finished
# watching, not from a snapshot midway: "the thief never got the mail" judged at
# second six cannot see a delivery at second nine.
try { $thief.WaitForExit() } catch { }
$thiefTxt = Read-Text $outT
$thiefRegistered = $thiefTxt -match ('registered as #' + $ownerNum)
$thiefSawMail = $thiefTxt.IndexOf($canary) -ge 0
"the thief was refused: $refused"
"the thief reached 'registered as': $thiefRegistered   (must be False)"
"the thief received the queued message: $thiefSawMail   (must be False)"

# --- the owner comes back ---
try { if (-not $thief.HasExited) { $thief.Kill() } } catch { }
Start-Sleep -Seconds 1
$o2 = Start-Node $dirO @("--home=$dirO", "--number=$ownerNum", "--relay=127.0.0.1:$port", '--watch=70') $outO2
$got = $false
$ready = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outO2).IndexOf($canary) -ge 0) { $got = $true; break }
  Start-Sleep -Milliseconds 400
}
"the owner returned and got their message: $got"
Start-Sleep -Seconds 2
$o2Txt = Read-Text $outO2
$warned = $o2Txt -match ('tried to register #' + $ownerNum)
"the owner was told someone tried to take their number: $warned"
$relayTxt = Read-Text $outR

Start-Sleep -Seconds 2
try { if (-not $o2.HasExited) { $o2.Kill() } } catch { }
try { if (-not $send.HasExited) { $send.Kill() } } catch { }
try { if (-not $relay.HasExited) { $relay.Kill() } } catch { }
Start-Sleep -Seconds 2

# --- the escape hatch, exercised the way an operator would reach for it ---
# A lease with no way out is a lockout, and a lockout is worse than the hole this
# closes. So the release has to work from the command line, across processes, and
# the number genuinely becomes claimable again afterwards - which is the accepted
# trade: whoever runs the relay is the one person who can always hand a number over.
$relay2 = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone', `
                             "--release-number=$ownerNum", '--serve-timeout=90') $outR2
$releasedLine = $false
$ready = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR2) -match 'RELAY RELEASING') { $releasedLine = $true; break }
  if ($relay2.HasExited) { break }
  Start-Sleep -Milliseconds 250
}
"the relay reports releasing the number: $releasedLine"
Start-Sleep -Seconds 2
$thief2 = Start-Node $dirT @("--home=$dirT", "--number=$ownerNum", "--relay=127.0.0.1:$port", '--watch=20') $outT2
$afterRelease = $false
$ready = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outT2) -match ('registered as #' + $ownerNum)) { $afterRelease = $true; break }
  Start-Sleep -Milliseconds 300
}
"after an explicit release, the same install can register it: $afterRelease   (must be True)"
Start-Sleep -Seconds 2
try { if (-not $thief2.HasExited) { $thief2.Kill() } } catch { }
try { if (-not $relay2.HasExited) { $relay2.Kill() } } catch { }
Start-Sleep -Seconds 1

$checks = @()
$checks += @{ n = 'the owner registered once and the lease is on disk'; ok = ($claimed -and $leased); d = "claimed=$claimed lease=$leased" }
$checks += @{ n = 'the lease holds no copy of the shared token'; ok = (-not $plainToken); d = "plaintext=$plainToken" }
$checks += @{ n = 'the owner really was off-line for the attack'; ok = $ownerGone; d = '' }
$checks += @{ n = 'mail left for them was queued, not dropped'; ok = $queued; d = '' }
$checks += @{ n = 'a second install could not take the number by registering it'; ok = ($refused -and -not $thiefRegistered); d = "refused=$refused registered=$thiefRegistered" }
$checks += @{ n = '...so it never received the waiting message'; ok = (-not $thiefSawMail); d = '' }
$checks += @{ n = 'the real owner still gets their mail on return'; ok = $got; d = '' }
$checks += @{ n = 'and is told how often it was attempted'; ok = $warned; d = '' }
$checks += @{ n = 'the relay logged the refusal, for its operator'; ok = ($relayTxt -match ('Refused registration for ' + $ownerNum)); d = '' }
$checks += @{ n = 'the sealed message never appears in the relay log'; ok = (-not ($relayTxt.Contains($canary))); d = '' }
$checks += @{ n = 'an operator can release a lease from the command line'; ok = ($releasedLine -and $afterRelease); d = "line=$releasedLine reclaimable=$afterRelease" }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
'--- relay said (last 12) ---'; ($relayTxt -split "`n" | Select-Object -Last 12)
'--- thief said (last 6) ---'; ($thiefTxt -split "`n" | Select-Object -Last 6)
'--- owner on return (last 8) ---'; ($o2Txt -split "`n" | Select-Object -Last 8)

Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
if (-not $allOk) { exit 1 }
exit 0
