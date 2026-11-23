# The bootstrap, as it will really be used: a relay prints one line, a friend pastes
# it into relays.seed, and their app finds the relay without anybody typing an IP.
#
# Two things are proven here that a unit test cannot:
#   1. a seed entry with the right fingerprint is accepted, and the client says so
#      BEFORE it registers - the relay's own log is the witness;
#   2. a seed entry whose fingerprint does not match is refused, and the relay never
#      learns that the number exists. That second part is the entire reason a shared
#      list is safe to hand out at all.
#
#   relay    --serve                        (45875, prints SEED LINE)
#   friend   --bootstrap --watch=N         (no --relay= at all: seed only)
#
# Phase 3 is the one a person actually lives through: the window opened with no relay
# typed in, on a profile that only has the pasted seed line. Its witness is the relay's
# own log, because a registration arriving there with nobody having typed an address is
# the whole feature. (What this does NOT check: the pixels. The success line and the
# fingerprint are shown through the ordinary VoipService log pipe, which is what every
# other window message uses.)
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"

$port = 45875
$peerNum = '7003287001'
$base = Join-Path $env:TEMP 'opencode\bootstrap'
$dirR = Join-Path $base 'relay'
$dirA = Join-Path $base 'goodpin'
$dirB = Join-Path $base 'wrongpin'
$dirG = Join-Path $base 'window'
$outR = Join-Path $dirR 'relay_out.txt'
$outA = Join-Path $dirA 'client_out.txt'
$outB = Join-Path $dirB 'client_out.txt'
$outG = Join-Path $dirG 'client_out.txt'
$runLog = Join-Path $root 'diagnostics\bootstrap_e2e_run.txt'
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
  return $false
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
# Pull the "address|fingerprint" pair out of the relay's own SEED LINE. Parsed rather
# than retyped by hand, so a test that pastes a stale fingerprint cannot pass.
function SeedLineOf([string]$txt) {
  foreach ($l in ($txt -split "`n")) {
    if ($l -match 'SEED LINE (\S+)\|(\S+)\|') { return @{ addr = $Matches[1]; fp = $Matches[2] } }
  }
  return $null
}

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirR, $dirA, $dirB)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
$env:USSD_TRACE = '1'

# --- the relay, which is the only thing that knows its own fingerprint ---
# Long enough for all three phases: two headless clients and a window. A relay that
# timed out mid-run would make the last check fail for a reason that has nothing to do
# with what is being tested.
$relay = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone', `
                            '--serve-timeout=600') $outR
if (-not (Wait-For $outR 'RELAY UP' 25)) {
  'FAIL: the relay never came up; every later check would pass on an empty log'
  Read-Text (Join-Path $dirR 'err.txt')
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
Wait-For $outR 'SEED LINE' 10 | Out-Null
$seed = SeedLineOf (Read-Text $outR)
$relayTxt = Read-Text $outR
"relay printed a seed line: $(if ($seed) { 'yes' } else { 'no' })"
if (-not $seed) {
  ($relayTxt -split "`n" | Select-Object -Last 12)
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
"   address=$($seed.addr)  fingerprint=$($seed.fp)"

# --- friend 1: the line pasted as-is ---
Set-Content -Path (Join-Path $dirA 'relays.seed') -Value "# from Aisha`n$($seed.addr)|$($seed.fp)|Aisha's relay" -Encoding ascii
$a = Start-Node $dirA @("--home=$dirA", "--number=$peerNum", '--bootstrap', '--watch=30') $outA
$okA = Wait-For $outA 'HEADLESS number=' 45
$txtA = Read-Text $outA
"first friend connected through the seed: $(if ($okA) { 'yes' } else { 'no' })"
if (-not $okA) { ($txtA -split "`n" | Select-Object -Last 14) }

# --- friend 2: same address, fingerprint mistyped by one character ---
# Counted rather than guessed at: the tampered client mints its own number on first
# run, so "did that number appear" would ask about a number nobody knows. What can be
# asked is whether the relay saw any registration at all between the two attempts.
$regBefore = ([regex]::Matches((Read-Text $outR), 'Registered ')).Count
$bad = $seed.fp; if ($bad.Length -gt 2) { $bad = $bad.Substring(0, $bad.Length - 2) + '00' } else { $bad = 'DEADBEEF' }
Set-Content -Path (Join-Path $dirB 'relays.seed') -Value "# tampered`n$($seed.addr)|$bad|looks like Aisha's" -Encoding ascii
$b = Start-Node $dirB @("--home=$dirB", '--bootstrap', '--watch=25') $outB
$refused = Wait-For $outB 'BOOTSTRAP FAIL' 45
$txtB = Read-Text $outB
"a mismatched fingerprint was refused: $(if ($refused) { 'yes' } else { 'no' })"
if (-not $refused) { ($txtB -split "`n" | Select-Object -Last 14) }
Start-Sleep -Seconds 2
$regAfter = ([regex]::Matches((Read-Text $outR), 'Registered ')).Count

# --- phase 3: the window, with nothing typed in at all ---
# Same seed line, no --relay and no --bootstrap flag: an ordinary double-click. The
# number is fixed so the relay log can be asked about one specific registration rather
# than about a count that a keepalive re-REG would move under us.
$guiNum = '7003287003'
New-Item -ItemType Directory -Force -Path $dirG | Out-Null
Copy-Item $appExe -Destination (Join-Path $dirG 'UssdApp.exe') -Force
Set-Content -Path (Join-Path $dirG 'relays.seed') -Value "# from Aisha`n$($seed.addr)|$($seed.fp)|Aisha's relay" -Encoding ascii
$g = Start-Node $dirG @("--home=$dirG", "--number=$guiNum") $outG
$guiUp = Wait-For $outR ('Registered ' + $guiNum) 90
Start-Sleep -Seconds 2
$relayNow = Read-Text $outR
# A bootstrap that quietly rewrote the person's settings would be the same kind of
# lie as the STUN box that saved a value nothing read: the seed is a suggestion, not a
# new setting, so the config must still show no relay of its own. Asked positively (the
# field has to be there and empty), because "the file does not mention it" would also
# pass on a profile whose config was never written at all.
$guiCfg = Read-Text (Join-Path $dirG 'ussd_config.json')
$cfgQuiet = ($guiCfg -match '"relay_server"\s*:\s*""')
# 'Registered ' also appears inside 'Unregistered ', hence the lookbehind. A
# registration with no number after it could only have come from a probe.
$guiRegs = ([regex]::Matches($relayNow, ('(?<![A-Za-z])Registered ' + $guiNum))).Count
$emptyRegs = ([regex]::Matches($relayNow, '(?<![A-Za-z])Registered \s')).Count

$relayTxt = Read-Text $outR
$checks = @()
$checks += @{ n = 'the relay publishes a line a stranger can paste'; ok = ($seed.addr.Length -gt 3 -and $seed.fp.Length -gt 3); d = '' }
$checks += @{ n = 'the seed entry was accepted and the client came up'; ok = $okA; d = '' }
$checks += @{ n = '...and it says how the relay was verified'
             ok = ($txtA -match 'relay_trust=verified-(new|known)'); d = ('saw ' + (Select-String -InputObject $txtA -Pattern 'relay_trust=\S+' -AllMatches)) }
$checks += @{ n = '...and it shows the fingerprint it pinned, not just a green tick'
             ok = ($txtA -match ('relay_key=' + [regex]::Escape($seed.fp))); d = '' }
$checks += @{ n = 'the good client really registered (the relay saw it)'
             ok = ($relayTxt -match ('Registered ' + $peerNum)); d = '' }
$checks += @{ n = 'a fingerprint that does not match is refused outright'; ok = $refused; d = '' }
$checks += @{ n = '...and the refusal names the fingerprint it saw instead of a bare error'
             ok = ($txtB -match 'its fingerprint is '); d = '' }
$checks += @{ n = '...and the tampered attempt registered nothing at that relay'
             ok = ($regAfter -eq $regBefore)
             d = "registrations before=$regBefore after=$regAfter" }
$checks += @{ n = 'the window connected through the seed with no relay typed in'
             ok = $guiUp; d = '' }
$checks += @{ n = '...and it left the saved settings alone (no relay written into the config)'
             ok = $cfgQuiet; d = ('config says ' + (($guiCfg -split "`n" | Where-Object { $_ -match 'relay_server' }) -join ' ')) }
$checks += @{ n = '...and the relay logged that one registration, not two (the probe stayed quiet)'
             ok = ($guiRegs -ge 1 -and $emptyRegs -eq 0)
             d = "for this number=$guiRegs nameless=$emptyRegs" }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
''
'--- what the relay saw ---'
(($relayTxt -split "`n") | Where-Object { $_ -match 'Registered|Unregistered|RELAY STATUS|SEED LINE|WHOAMI' } | Select-Object -Last 8)
Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if ($allOk) { exit 0 } else { exit 1 }
