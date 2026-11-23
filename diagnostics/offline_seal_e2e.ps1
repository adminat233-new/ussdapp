# Offline sealing end-to-end across REAL PROCESSES.
#
# The claim being tested is one the in-process suite cannot make: that the shipped
# binary, on its own, leaves a message for a contact that is NOT connected - and
# that the bytes sitting on the relay are unreadable to whoever runs it.
#
# That case used to be impossible. A session key needs the peer awake, so mail for
# somebody off-line was plaintext in the relay's queue. A published identity key is
# what changes it: the sender fetches the key the contact left when they last
# registered, seals to it, and the relay stores something it cannot open.
#
#   relay  UssdApp.exe --serve --relay-carry-mail     (45861)
#   bob    registers once, publishes his key, then quits  (offline from here on)
#   alice  --send=bob|<canary>                        (never meets him)
#   bob    comes back and must read the message exactly once
#
# The assertions are made on the relay's own mail files, because that is the thing
# a relay's owner can actually inspect: "what is stored on my machine, and can I
# read it?"
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"
$port = 45861
$numA = '7003261101'   # alice, the sender
$numB = '7003261102'   # bob, off-line for almost the whole run
$canary = 'OFFLINE-SEAL-' + (Get-Date -Format 'HHmmss')
$base = Join-Path $env:TEMP 'opencode\oseal'
$dirR = Join-Path $base 'relay'; $dirA = Join-Path $base 'alice'; $dirB = Join-Path $base 'bob'
$outR = Join-Path $dirR 'relay_out.txt'; $outA = Join-Path $dirA 'send_out.txt'
$outB1 = Join-Path $dirB 'first_out.txt'; $outB2 = Join-Path $dirB 'back_out.txt'
$runLog = Join-Path $root 'diagnostics\offline_seal_run.txt'
try { Start-Transcript -Path $runLog -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}
function MailText([string]$d) {
  $t = ''
  # -Filter is matched by the OS, which also consults 8.3 aliases, so *.mail can
  # return a half-written "<id>.mail.<ticks>.part". A stray temp file must never
  # count as mail that is still waiting - the relay itself refuses to read it.
  foreach ($f in (Get-ChildItem (Join-Path $d 'mail') -Filter *.mail -Force -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name.EndsWith('.mail', [System.StringComparison]::OrdinalIgnoreCase) })) {
    $t += (Read-Text $f.FullName) + "`n"
  }
  return $t
}

# A leftover run of THIS script is the thing to fear: it holds the port, and once
# its exe file has been deleted the process Path no longer resolves, so matching on
# Path silently skips it. The command line still carries --home=, so match on that.
function Kill-Leftovers([string]$base) {
  try {
    $cs = Get-CimInstance Win32_Process -Filter "Name='UssdApp.exe' OR Name='UssdAgent.exe'" -ErrorAction SilentlyContinue
    foreach ($c in $cs) {
      if ($c.CommandLine -and $c.CommandLine.Contains($base)) {
        try { Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue } catch { }
      }
    }
  } catch { }
}
Kill-Leftovers $base
Start-Sleep -Seconds 2
# The whole scratch tree goes, not just the profile files: leaving an old
# UssdApp.exe behind means the next line-up silently tests THAT instead of the
# binary asked for, which is exactly how one run of this harness once lied.
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirR, $dirA, $dirB)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  # Explicit destination file name: copying a build that is not called
  # UssdApp.exe must still land as UssdApp.exe, or the launch below runs a
  # different binary than the one reported on the first line.
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
  Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $d -Force -ErrorAction SilentlyContinue
}
$env:USSD_TRACE = '1'

# --- the relay, willing to carry ---
$relay = Start-Process -FilePath (Join-Path $dirR 'UssdApp.exe') `
  -ArgumentList @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone', `
                  '--relay-carry-mail', '--serve-timeout=190') `
  -WorkingDirectory $dirR -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outR -RedirectStandardError (Join-Path $dirR 'relay_err.txt')
# Gate everything on the relay actually listening. If it could not bind, every
# check below would pass vacuously - nothing printed the canary, nothing was
# stored, the store was empty - and the run would report success having tested
# nothing. That is the single worst way for a harness to be wrong.
$up = $false
$ready = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match 'RELAY UP') { $up = $true; break }
  if ($relay.HasExited) { break }
  Start-Sleep -Milliseconds 250
}
if (-not $up) {
  "FAIL: the relay never came up on port $port"
  '--- relay stderr ---'; (Read-Text (Join-Path $dirR 'relay_err.txt'))
  Kill-Leftovers $base
  try { Stop-Transcript | Out-Null } catch { }
  exit 1
}
"relay up: $up  (carry mail on, onion off)"

# --- bob registers once, so his key is on file, then leaves ---
$bob1 = Start-Process -FilePath (Join-Path $dirB 'UssdApp.exe') `
  -ArgumentList @("--home=$dirB", "--number=$numB", "--relay=127.0.0.1:$port", '--linger=12') `
  -WorkingDirectory $dirB -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outB1 -RedirectStandardError (Join-Path $dirB 'bob1_err.txt')
$published = $false
$ready = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match 'Peer key stored for #' + $numB) { $published = $true; break }
  Start-Sleep -Milliseconds 300
}
"bob published an identity key while he was connected: $published"
try { if (-not $bob1.HasExited) { $bob1.Kill() } } catch { }
Start-Sleep -Seconds 2
# Confirm he really is gone before anything is sent to him: the whole point of the
# test is a recipient who cannot be reached.
$gone = (Read-Text $outR) -match 'Unregistered ' + $numB
"bob is off-line again: $gone"

# --- alice sends to a contact she has never met, while he is away ---
$alice = Start-Process -FilePath (Join-Path $dirA 'UssdApp.exe') `
  -ArgumentList @("--home=$dirA", "--number=$numA", "--relay=127.0.0.1:$port", `
                  "--send=$numB|$canary", '--watch=60') `
  -WorkingDirectory $dirA -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outA -RedirectStandardError (Join-Path $dirA 'alice_err.txt')

# Wait for the relay to hold something for him.
$queued = $false
$ready = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outR) -match 'Queued offline message for ' + $numB) { $queued = $true; break }
  Start-Sleep -Milliseconds 400
}
"the relay queued alice's message for the off-line contact: $queued"
Start-Sleep -Seconds 2
$mail = MailText $dirR
$relayOut = Read-Text $outR
$aliceOut = Read-Text $outA

# --- and now the part that is the actual point of the feature ---
$sealedOnDisk = $mail.IndexOf('ECHATK|') -ge 0
$readable = $mail.IndexOf($canary) -ge 0
$relaySawPlain = $relayOut.IndexOf($canary) -ge 0

# --- bob comes back: the queue is flushed, and he must be able to read it ---
$bob2 = Start-Process -FilePath (Join-Path $dirB 'UssdApp.exe') `
  -ArgumentList @("--home=$dirB", "--number=$numB", "--relay=127.0.0.1:$port", '--watch=70') `
  -WorkingDirectory $dirB -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $outB2 -RedirectStandardError (Join-Path $dirB 'bob2_err.txt')
$read = $false
$ready = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $ready) {
  if ((Read-Text $outB2).IndexOf($canary) -ge 0) { $read = $true; break }
  Start-Sleep -Milliseconds 400
}
"bob read the message after coming back: $read"
Start-Sleep -Seconds 3
try { if (-not $bob2.HasExited) { $bob2.Kill() } } catch { }
try { if (-not $alice.HasExited) { $alice.Kill() } } catch { }
Start-Sleep -Seconds 1
try { if (-not $relay.HasExited) { $relay.Kill() } } catch { }
Start-Sleep -Seconds 1

$b2 = Read-Text $outB2
$got = ([regex]::Matches($b2, 'INBOUND chat from #' + $numA + ': ' + [regex]::Escape($canary))).Count
$leftAfter = MailText $dirR

$checks = @()
$checks += @{ n = 'bob published a key while connected, alice never met him'; ok = $published; d = '' }
$checks += @{ n = 'the recipient really was off-line'; ok = $gone; d = '' }
$checks += @{ n = "alice's send was accepted for an unreachable contact"; ok = ($aliceOut -match 'SendChat -> True'); d = '' }
# Asserted on what alice actually printed, not on her RESULT line: she is still
# watching when the run ends, so that line is never written - and a check on it
# fails for the wrong reason.
$checks += @{ n = 'alice sealed it to a key she had never used in a session'; ok = ($aliceOut -match 'sealed to #' + $numB + "'s published key"); d = '' }
$checks += @{ n = 'no key exchange was filed as mail for the absent peer'; ok = ($mail.IndexOf('|KEYX|') -lt 0); d = '' }
$checks += @{ n = 'the relay queued the message instead of dropping it'; ok = $queued; d = '' }
$checks += @{ n = 'WHAT IS STORED IS SEALED (ECHATK in the mail file)'; ok = $sealedOnDisk; d = '' }
$checks += @{ n = 'THE RELAY CANNOT READ THE MESSAGE (no canary in its mail)'; ok = (-not $readable); d = "readable=$readable" }
$checks += @{ n = 'nor in anything it printed'; ok = (-not $relaySawPlain); d = '' }
$checks += @{ n = 'the recipient opens it when they come back'; ok = $read; d = '' }
$checks += @{ n = 'and exactly once'; ok = ($got -eq 1); d = "inbound lines=$got" }
$checks += @{ n = 'the store is empty afterwards (delivered, not lingering)'; ok = ($leftAfter.Length -eq 0); d = "left=$($leftAfter.Length)" }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
'--- what the relay is storing (first 220 chars) ---'
if ($mail.Length -gt 0) { $mail.Substring(0, [Math]::Min(220, $mail.Length)) } else { '(nothing)' }
'--- relay said (last 10) ---'; ($relayOut -split "`n" | Select-Object -Last 10)
'--- bob said on return (last 8) ---'; ($b2 -split "`n" | Select-Object -Last 8)

Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith($base, 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
if (-not $allOk) { exit 1 }
exit 0
