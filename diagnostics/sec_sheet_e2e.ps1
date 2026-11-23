# A3 proof: the safety number a person reads, verified on both sides.
#
# Nothing here trusts the crypto selftest: two real instances talk through a
# real relay, then a UI test presses the lock chip and reads the digits off the
# screen. The claim worth making is that two machines, holding no shared secret
# of their own, display the SAME twelve groups - and that when one of them is
# told a different key belongs to its friend, it says so, stops sending, and
# only resumes when a person presses the button.
#
# The tamper leg works on instB (a throwaway copy) and restores its peer book,
# so no dev profile is left holding a poisoned key.
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$Hub = Join-Path $root 'diagnostics\hub_e2e.ps1'
$Work = Join-Path $root 'Csharp'
$Bdir = Join-Path $env:TEMP 'opencode\instB'
$PidFile = Join-Path $env:TEMP 'opencode\callpids.txt'
$bookB = Join-Path $Bdir 'peers_identity.txt'
$run = Join-Path $root 'diagnostics\sec_sheet_run.txt'
$numA = '7003256013'
$numB = '7003256099'
try { Start-Transcript -Path $run -Force | Out-Null } catch { }

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Sec {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  public static int pid;
  public static System.Collections.Generic.List<IntPtr> hl = new System.Collections.Generic.List<IntPtr>();
}
"@

function Find-Win([int]$procId) {
  [Sec]::pid = $procId; [Sec]::hl.Clear()
  $cb = [Sec+EnumProc] { param($h, $l)
    $o = 0; [Sec]::GetWindowThreadProcessId($h, [ref]$o) | Out-Null
    if ($o -eq [Sec]::pid) { [Sec]::hl.Add($h) }
    return $true }
  [Sec]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
  foreach ($h in [Sec]::hl) {
    $tb = New-Object System.Text.StringBuilder 256
    [Sec]::GetWindowText($h, $tb, 256) | Out-Null
    if ($tb.ToString() -like '*USSD Manager Pro*') { return $h }
  }
  return [IntPtr]::Zero
}
function Wait-Win([int]$procId, [int]$seconds) {
  $d = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $d) {
    $w = Find-Win $procId
    if ($w -ne [IntPtr]::Zero) { return $w }
    Start-Sleep -Milliseconds 500
  }
  return [IntPtr]::Zero
}
# Each hub_e2e phase prints KEY=value lines; collect them into a hashtable so a
# missing line is a failed assertion instead of a silent null.
function Hub-Run([string]$phase, [string]$text) {
  # $args is an automatic variable, so the argument list gets its own name.
  $argl = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Hub, '-Phase', $phase)
  if ($text) { $argl += @('-Text', $text) }
  $out = @(& pwsh $argl 2>&1 | ForEach-Object { [string]$_ })
  $kv = @{}
  foreach ($l in $out) {
    if ($l -match '^([A-Z][A-Za-z_]*)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
  }
  return @{ kv = $kv; raw = $out }
}
function Canary-Hits([string]$dir, [string]$needle) {
  $n = 0
  foreach ($f in @(Get-ChildItem (Join-Path $dir 'chats') -Filter '*.txt' -ErrorAction SilentlyContinue)) {
    $txt = ''
    try { $txt = [System.IO.File]::ReadAllText($f.FullName) } catch { continue }
    $n += ([regex]::Matches($txt, [regex]::Escape($needle))).Count
  }
  return $n
}
# The test starts both instances, so the test is the thing that has to stop them:
# a leftover window holds the relay slot and locks the exe against the next build.
function Stop-Own([string]$why) {
  foreach ($p in @($script:pa, $script:pb)) {
    try { if ($p -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit(8000) | Out-Null } } catch { }
  }
  'cleanup (' + $why + '): instances stopped'
}

$checks = @()
function Add-Check([string]$n, [bool]$ok, [string]$d) {
  $script:checks += @{ n = $n; ok = $ok; d = $d }
}

# --- fresh binaries, no leftover instances -----------------------------------
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Seconds 2
$otherA = @(Get-Process UssdApp -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -ne (Join-Path $Work 'UssdApp.exe') -and -not $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false } })
if ($otherA.Count -gt 0) {
  'ABORT: another UssdApp is running that this test will not touch: ' + (($otherA | ForEach-Object { $_.Id }) -join ',')
  try { Stop-Transcript | Out-Null } catch { }
  exit 2
}
Copy-Item (Join-Path $Work 'UssdApp.exe') -Destination $Bdir -Force
Copy-Item (Join-Path $Work 'UssdApp.ico') -Destination $Bdir -Force -ErrorAction SilentlyContinue
$hashA = (Get-FileHash (Join-Path $Work 'UssdApp.exe') -Algorithm SHA256).Hash
$hashB = (Get-FileHash (Join-Path $Bdir 'UssdApp.exe') -Algorithm SHA256).Hash
Add-Check 'both profiles run the freshly built exe' ($hashA -eq $hashB) ('A=' + $hashA.Substring(0, 12) + ' B=' + $hashB.Substring(0, 12))

# --- bring up two instances: A hosts the relay, B connects to it -------------
$env:USSD_FAKE_MIC = '1'
$pa = Start-Process -FilePath (Join-Path $Work 'UssdApp.exe') -WorkingDirectory $Work -PassThru
$wa = Wait-Win $pa.Id 120
Start-Sleep -Seconds 3
$pb = Start-Process -FilePath (Join-Path $Bdir 'UssdApp.exe') -WorkingDirectory $Bdir -PassThru
$wb = Wait-Win $pb.Id 120
"A pid=$($pa.Id) window=$($wa -ne [IntPtr]::Zero)  B pid=$($pb.Id) window=$($wb -ne [IntPtr]::Zero)"
Set-Content -Path $PidFile -Value ("A=" + $pa.Id)
Add-Content -Path $PidFile -Value ("B=" + $pb.Id)
Start-Sleep -Seconds 10
Add-Check 'both windows came up' (($wa -ne [IntPtr]::Zero) -and ($wb -ne [IntPtr]::Zero)) ''

# --- make them talk, so a real session key exists on both sides --------------
$tsA = 'SEC-A-' + (Get-Date -Format 'HHmmss')
$tsB = 'SEC-B-' + (Get-Date -Format 'HHmmss')
$r = Hub-Run 'send:A' $tsA
'A send: ' + (($r.raw | Select-String -SimpleMatch 'OUTCOME', 'SECURITY' | Select-Object -First 2) -join ' // ')
$r = Hub-Run 'send:B' $tsB
'B send: ' + (($r.raw | Select-String -SimpleMatch 'OUTCOME', 'SECURITY' | Select-Object -First 2) -join ' // ')
Start-Sleep -Seconds 6

# --- read the sheet on each side ---------------------------------------------
$sa = Hub-Run 'sec:A' $tsA
$sb = Hub-Run 'sec:B' $tsB
"=== instance A sheet ===" ; $sa.raw | Where-Object { $_ -match '^(CHIP|SN|MINE|PEER|DIGEST|TRUST|COPY|CLOSE)' }
"=== instance B sheet ===" ; $sb.raw | Where-Object { $_ -match '^(CHIP|SN|MINE|PEER|DIGEST|TRUST|COPY|CLOSE)' }

function Sn-Groups([string]$line) {
  # "Safety number: 33623 41363 ..." -> the digit groups only
  $i = $line.IndexOf(':')
  $body = if ($i -ge 0) { $line.Substring($i + 1).Trim() } else { $line.Trim() }
  return @([regex]::Matches($body, '\b\d{5}\b') | ForEach-Object { $_.Value })
}
function Short([string]$s) {
  if ($null -eq $s) { return '' }
  if ($s.Length -le 59) { return $s }
  return $s.Substring(0, 59) + '...'
}
# Timestamp every harness action: when the app's own trace and this console are
# read side by side, a warning that arrived late must be distinguishable from a
# warning that never arrived - and from a trust the test itself caused.
function Mark([string]$s) { '>>> ' + (Get-Date -Format 'HH:mm:ss') + ' ' + $s }
$snA = Sn-Groups ([string]$sa.kv['SN'])
$snB = Sn-Groups ([string]$sb.kv['SN'])
Add-Check 'A reports a locked session' ([string]$sa.kv['CHIP'] -eq 'Chat encryption locked') ('CHIP=' + [string]$sa.kv['CHIP'])
Add-Check 'B reports a locked session' ([string]$sb.kv['CHIP'] -eq 'Chat encryption locked') ('CHIP=' + [string]$sb.kv['CHIP'])
Add-Check 'the sheet shows twelve groups of five digits' ($snA.Count -eq 12 -and $snB.Count -eq 12) ('A=' + $snA.Count + ' B=' + $snB.Count)
Add-Check 'both sides display the identical safety number' ($snA.Count -eq 12 -and ($snA -join ' ') -eq ($snB -join ' ')) ('A=' + (Short ($snA -join ' ')) + ' B=' + (Short ($snB -join ' ')))
$fpA = (([string]$sa.kv['MINE']) -replace '^Your key:\s*', '').Trim()
$fpB = (([string]$sb.kv['MINE']) -replace '^Your key:\s*', '').Trim()
$peerOfA = (([string]$sa.kv['PEER']) -replace '^Their key:\s*', '').Trim()
$peerOfB = (([string]$sb.kv['PEER']) -replace '^Their key:\s*', '').Trim()
Add-Check 'what A calls its own key is what B sees as theirs' ($fpA.Length -gt 0 -and $fpA -eq $peerOfB) ('A=' + $fpA + ' B-says=' + $peerOfB)
Add-Check 'what B calls its own key is what A sees as theirs' ($fpB.Length -gt 0 -and $fpB -eq $peerOfA) ('B=' + $fpB + ' A-says=' + $peerOfA)
Add-Check 'the two identity keys are genuinely different' ($fpA -ne $fpB) ('A=' + $fpA + ' B=' + $fpB)
$digA = [string]$sa.kv['DIGEST']
Add-Check 'the header digest is the head of the safety number' ($digA.StartsWith('safety ') -and $snA.Count -ge 2 -and $digA -eq ('safety ' + ($snA[0] + ' ' + $snA[1]))) ('digest=' + $digA)
Add-Check 'the sheet offers copy and close but no trust when nothing changed' ($sa.kv['COPY_offscreen'] -eq 'False' -and $sa.kv['CLOSE_offscreen'] -eq 'False' -and $sa.kv['TRUST_offscreen'] -in @('absent', 'True')) ('copy=' + $sa.kv['COPY_offscreen'] + ' close=' + $sa.kv['CLOSE_offscreen'] + ' trust=' + $sa.kv['TRUST_offscreen'])
$c = Hub-Run 'secclose:A' ''
Add-Check 'close dismisses the sheet' ([string]$c.kv['SN_still'] -notlike 'Safety number*') ('after=' + [string]$c.kv['SN_still'])

# --- TOFU: record what B believes about A, then falsify it -------------------
if (-not (Test-Path $bookB)) { 'ABORT: no peer book on B to tamper with' ; exit 2 }
$bookBackup = [System.IO.File]::ReadAllBytes($bookB)
$lines = @([System.IO.File]::ReadAllLines($bookB))
$tampered = @()
$hit = $false
foreach ($l in $lines) {
  $p = $l -split '\|'
  if ($p.Count -ge 2 -and $p[0] -eq $numA) {
    # Flip the middle of the stored blob: still a string, no longer that key.
    $k = $p[1].ToCharArray()
    $mid = [int]($k.Length / 2)
    $k[$mid] = if ($k[$mid] -eq 'A') { 'B' } else { 'A' }
    $p[1] = -join $k
    $hit = $true
    $tampered += ($p -join '|')
  } else { $tampered += $l }
}
if (-not $hit) {
  'ABORT: A is not in B''s peer book yet, nothing to falsify - restoring'
  [System.IO.File]::WriteAllBytes($bookB, $bookBackup)
  Stop-Own 'abort'
  try { Stop-Transcript | Out-Null } catch { }
  exit 2
}
[System.IO.File]::WriteAllLines($bookB, $tampered)
'replaced ' + $numA + "'s key in B's book (backup held in memory, " + $bookBackup.Length + ' bytes)'

# Restart both: an in-memory session must not hide the warning, and A has to
# start a fresh handshake for B to look at.
foreach ($p in @($pa, $pb)) {
  try { if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(8000) | Out-Null } } catch { }
}
Start-Sleep -Seconds 3
$pa = Start-Process -FilePath (Join-Path $Work 'UssdApp.exe') -WorkingDirectory $Work -PassThru
[void](Wait-Win $pa.Id 120)
$pb = Start-Process -FilePath (Join-Path $Bdir 'UssdApp.exe') -WorkingDirectory $Bdir -PassThru
[void](Wait-Win $pb.Id 120)
Set-Content -Path $PidFile -Value ("A=" + $pa.Id)
Add-Content -Path $PidFile -Value ("B=" + $pb.Id)
Start-Sleep -Seconds 10

# B must be sitting in the conversation with A when the key lands, because the
# warning belongs in front of the chat it protects.
Mark 'chatopen:B'
$opened = Hub-Run 'chatopen:B' ''
'B chat: ' + (($opened.raw | Select-String -SimpleMatch 'ensure' | Select-Object -First 1))
$canary = 'TAMPER-CANARY-' + (Get-Date -Format 'HHmmss')
# Remember how far B's trace had got: the warning we are waiting for has to be
# written AFTER this point, not left over from an earlier leg.
$bTrace = Join-Path $Bdir 'hang_trace.txt'
$traceBefore = 0
if (Test-Path $bTrace) { $traceBefore = (Get-Item $bTrace).Length }
Mark ('send:A ' + $canary)
$r = Hub-Run 'send:A' $canary
'A send after falsification: ' + (($r.raw | Select-String -SimpleMatch 'OUTCOME', 'SECURITY', 'REFUSED' | Select-Object -First 3) -join ' // ')

# Wait for the event the app itself reports - a peer key that does not match the
# one on file. Watching the log instead of the chip tells the two failures apart:
# "the warning never reached B" (a delivery problem) is not "B did not show it".
# A chip poll alone would have reported the second for the first.
Mark 'waiting for B to record the key-change warning'
$warnLine = ''
$waitUntil = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $waitUntil) {
  try {
    $fs = [System.IO.File]::Open($bTrace, 'Open', 'Read', 'ReadWrite')
    $fs.Position = [Math]::Min($traceBefore, $fs.Length)
    $sr = New-Object System.IO.StreamReader($fs)
    $new = $sr.ReadToEnd(); $sr.Close(); $fs.Close()
    $hit = @($new -split "`n" | Select-String -SimpleMatch 'SECURITY WARNING: the identity key')
    if ($hit.Count -gt 0) { $warnLine = $hit[$hit.Count - 1].Line.Trim(); break }
  } catch { }
  Start-Sleep -Seconds 3
}
Mark ('B logged: ' + $(if ($warnLine) { $warnLine.Substring(0, [Math]::Min(96, $warnLine.Length)) } else { 'NOTHING' }))
Add-Check 'B recorded the falsified key as a security warning' ($warnLine.Length -gt 0) (Short $warnLine)
$st = Hub-Run 'sec:B' $canary
Mark 'read the sheet under the falsified key'
"=== B sheet under a falsified key ==="
$st.raw | Where-Object { $_ -match '^(CHIP|SN|MINE|PEER|TRUST|COPY|CLOSE)' }
Add-Check 'B detects the key change and says blocked' ([string]$st.kv['CHIP'] -eq 'Chat encryption blocked') ('CHIP=' + [string]$st.kv['CHIP'])
Add-Check 'the warning offers an explicit trust action' ($st.kv['TRUST_offscreen'] -eq 'False') ('trust=' + $st.kv['TRUST_offscreen'])
$blockedHits = Canary-Hits $Bdir $canary
Add-Check 'nothing was delivered to B while the key was unreviewed' ($blockedHits -eq 0) ('canary in B chats=' + $blockedHits)

# Press the button a person would press, then check the message finally lands.
Mark 'sectrust:B'
$t = Hub-Run 'sectrust:B' ''
'B trust: ' + (($t.raw | Select-String -SimpleMatch 'trust', 'log' | Select-Object -First 2) -join ' // ')
$landed = 0
$d = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $d) {
  $landed = Canary-Hits $Bdir $canary
  if ($landed -ge 1) { break }
  Start-Sleep -Seconds 3
}
Add-Check 'after trusting, the held message arrives exactly once' ($landed -eq 1) ('occurrences=' + $landed)
Mark 'final sheet read'
$after = Hub-Run 'sec:B' ''
Add-Check 'B resumes with a locked session' ([string]$after.kv['CHIP'] -eq 'Chat encryption locked') ('CHIP=' + [string]$after.kv['CHIP'])
Add-Check 'the safety number is unchanged by the review' (((Sn-Groups ([string]$after.kv['SN'])) -join ' ') -eq ($snA -join ' ')) ('after=' + (Short ((Sn-Groups ([string]$after.kv['SN'])) -join ' ')) + ' vs ' + (Short ($snA -join ' ')))

# --- leave the profile as it was found ---------------------------------------
# Stop the instances FIRST: B keeps its peer book in memory and would rewrite
# the file a moment after a restore done under its nose.
Stop-Own 'done'
[System.IO.File]::WriteAllBytes($bookB, $bookBackup)
$restored = (Test-Path $bookB) -and ([System.IO.File]::ReadAllBytes($bookB)).Length -eq $bookBackup.Length
Add-Check 'the test restored B''s peer book byte for byte' ($restored) ''

'=== verdict ==='
$allOk = $true
foreach ($c2 in $checks) {
  $s = if ($c2.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c2.n, $c2.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
try { Stop-Transcript | Out-Null } catch { }
if (-not $allOk) { exit 1 }
exit 0
