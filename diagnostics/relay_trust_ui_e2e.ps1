# The relay's identity, as a person sees it - in the window, not in a log.
#
# conf_mixer_test.cs proves the pinning verdict exists and bootstrap_e2e.ps1 proves the
# window can find a relay from a pasted seed line. Neither proves the thing that actually
# protects anybody: that the fingerprint is on the screen, where it can be read against
# the relay's own console, and that the option which reroutes a call is a control and not
# a decoration.
#
# So this starts a real relay, opens a real window on a profile that has only a seed line
# (no relay typed in), and drives the UI through UIA:
#
#   relay      --serve 45877                     prints SEED LINE
#   window     --home=<fresh> --number=...       bootstraps from relays.seed
#
# Checks are made against the elements' own names and text, and the config file the app
# writes - not against a log line that asserts its own success.
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$appExe = if ($Exe) { $Exe } else { Join-Path $root 'Csharp\UssdApp.exe' }
if (-not (Test-Path $appExe)) { "FAIL: no binary at $appExe"; exit 2 }
"binary under test: $appExe"

$port = 45877
$winNum = '7003287009'
$base = Join-Path $env:TEMP 'opencode\trustui'
$dirR = Join-Path $base 'relay'
$dirG = Join-Path $base 'window'
$outR = Join-Path $dirR 'relay_out.txt'
$outG = Join-Path $dirG 'win_out.txt'
$runLog = Join-Path $root 'diagnostics\trust_ui_run.txt'

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class TrustUi {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  public static int pid;
  public static System.Collections.Generic.List<IntPtr> hl = new System.Collections.Generic.List<IntPtr>();
}
"@
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
function Find-Win([int]$procId) {
  [TrustUi]::pid = $procId; [TrustUi]::hl.Clear()
  $cb = [TrustUi+EnumProc] { param($h, $l)
    $o = 0; [TrustUi]::GetWindowThreadProcessId($h, [ref]$o) | Out-Null
    if ($o -eq [TrustUi]::pid) { [TrustUi]::hl.Add($h) }
    return $true }
  [TrustUi]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
  foreach ($h in [TrustUi]::hl) {
    $tb = New-Object System.Text.StringBuilder 256
    [TrustUi]::GetWindowText($h, $tb, 256) | Out-Null
    if ($tb.ToString() -like '*USSD Manager Pro*') { return $h }
  }
  return [IntPtr]::Zero
}
function Find-ByName([IntPtr]$hwnd, [string]$name) {
  try {
    $r = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    $cond = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::NameProperty, $name)
    return $r.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
  } catch { return $null }
}
function Text-Containing([IntPtr]$hwnd, [string]$needle) {
  try {
    $r = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    $ct = [System.Windows.Automation.ControlType]::Text
    $all = $r.FindAll([System.Windows.Automation.TreeScope]::Descendants,
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ct)))
    foreach ($e in $all) { if (([string]$e.Current.Name).Contains($needle)) { return [string]$e.Current.Name } }
  } catch { }
  return ''
}
# Found by its TEXT, not by an automation Name. That is the point: on a TextBlock the
# Name is what a screen reader speaks, so a widget named "Relay identity" and hiding the
# fingerprint in its content would be found here and unreadable by a person.
function Find-ByTextPrefix([IntPtr]$hwnd, [string]$prefix) {
  try {
    $r = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    $ct = [System.Windows.Automation.ControlType]::Text
    $all = $r.FindAll([System.Windows.Automation.TreeScope]::Descendants,
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ct)))
    foreach ($e in $all) {
      if (([string]$e.Current.Name).StartsWith($prefix, [System.StringComparison]::Ordinal)) { return $e }
    }
  } catch { }
  return $null
}
# UIA gives a WPF ToolTip as HelpText. That matters here: the caveat is part of the
# control, so it can be checked rather than assumed from the source file.
function Help-Of($el) { try { return [string]$el.Current.HelpText } catch { return '' } }
# The log is a FlowDocument, and a FlowDocument does NOT expose its paragraphs as child
# Text elements the way a StackPanel of TextBlocks does - the text comes out through the
# document's text pattern. Searching only ControlType.Text finds the Settings labels and
# silently misses every log line, which is exactly the kind of "not found, therefore not
# there" mistake this suite exists to avoid.
function Doc-Text([IntPtr]$hwnd) {
  $all = ''
  try {
    $r = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    $cond = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
      [System.Windows.Automation.ControlType]::Document)
    foreach ($e in $r.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)) {
      $pat = $null
      if ($e.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$pat)) {
        try { $all += ($pat.DocumentRange.GetText(-1)) + "`n" } catch { }
      }
    }
  } catch { }
  return $all
}

Kill-Leftovers $base
Start-Sleep -Seconds 2
try { Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
foreach ($d in @($dirR, $dirG)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Copy-Item $appExe -Destination (Join-Path $d 'UssdApp.exe') -Force
}
$env:USSD_TRACE = '1'
$env:USSD_FAKE_MIC = '1'

# --- the relay, and the line its owner would send ---------------------------
$relay = Start-Node $dirR @('--serve', "--port=$port", "--home=$dirR", '--relay-policy=everyone',
                            '--serve-timeout=240') $outR
if (-not (Wait-For $outR 'RELAY UP' 30)) {
  'FAIL: the relay never bound port ' + $port + ' - every check below would pass on an empty window'
  Read-Text (Join-Path $dirR 'err.txt')
  Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1
}
Wait-For $outR 'SEED LINE' 12 | Out-Null
$seedAddr = ''; $seedFp = ''
foreach ($l in ((Read-Text $outR) -split "`n")) {
  if ($l -match 'SEED LINE (\S+)\|(\S+)\|') { $seedAddr = $Matches[1]; $seedFp = $Matches[2]; break }
}
"relay seed line: $seedAddr | $seedFp"
if (-not $seedFp) { Kill-Leftovers $base; try { Stop-Transcript | Out-Null } catch { }; exit 1 }

Set-Content -Path (Join-Path $dirG 'relays.seed') -Value "# from Aisha`n$seedAddr|$seedFp|Aisha's relay" -Encoding ascii

# --- the window: nothing typed in, only the pasted line ---------------------
$g = Start-Node $dirG @("--home=$dirG", "--number=$winNum") (Join-Path $dirG 'launch_out.txt')
# The witness that the window connected is the relay's log, not the app's own words:
# a window writes nothing to stdout, and its log lines would be asserting their own
# success.
$bootstrapped = Wait-For $outR ('Registered ' + $winNum) 90
"the window came up and registered through the seed: $bootstrapped"

$hwnd = [IntPtr]::Zero
$chip = $null; $tick = $null
$end = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $end) {
  if ($hwnd -eq [IntPtr]::Zero) { $hwnd = Find-Win $g.Id; if ($hwnd -ne [IntPtr]::Zero) { [TrustUi]::ShowWindow($hwnd, 9) | Out-Null } }
  if ($hwnd -ne [IntPtr]::Zero) {
    $chip = Find-ByTextPrefix $hwnd 'Relay identity:'
    $tick = Find-ByName $hwnd 'Route calls through the relay'
    if ($chip -and $tick) { break }
  }
  Start-Sleep -Milliseconds 500
}

$chipText = Text-Containing $hwnd 'Relay identity:'
"the identity line on screen: $chipText"
$tickHelp = Help-Of $tick

# --- toggle the media option and see whether it reaches the config ----------
function Toggle-It($el) {
  try {
    $pat = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pat)) { $pat.Toggle(); return $true }
  } catch { }
  return $false
}
$toggledOn = $false
if ($tick) { $toggledOn = Toggle-It $tick }
$cfgOn = Wait-For (Join-Path $dirG 'ussd_config.json') '"relay_media"\s*:\s*true' 25
$toggledOff = $false
if ($toggledOn) {
  $tick2 = Find-ByName $hwnd 'Route calls through the relay'
  if ($tick2) { $toggledOff = Toggle-It $tick2 }
}
$cfgOff = Wait-For (Join-Path $dirG 'ussd_config.json') '"relay_media"\s*:\s*false' 25

$checks = @()
$checks += @{ n = 'the window found a relay from the pasted seed line alone'
             ok = $bootstrapped; d = '' }
$checks += @{ n = 'the window shows a relay-identity line, as text a reader can speak'
             ok = ($null -ne $chip -and $chipText.Length -gt 0); d = ('found: ' + ([bool]$chip)) }
$checks += @{ n = '...and the text on screen carries the fingerprint the relay printed'
             ok = ($chipText.Contains($seedFp)); d = ('saw: ' + $chipText) }
$checks += @{ n = '...and it says which of the two states this is, rather than just "connected"'
             ok = ($chipText -match 'pinned|unverified|NOT the one'); d = '' }
# The copy check. An option that reroutes media is easy to sell as privacy and is not:
# the address still reaches the peer through the directory. Assert the caveat is on the
# control itself, where it can be read, rather than only in a markdown file.
$checks += @{ n = '...and the media option states plainly that it does not hide your address'
             ok = ($tickHelp -match 'does not hide'); d = ('tooltip: ' + $tickHelp) }
$checks += @{ n = 'the relay-media switch exists as a real control'
             ok = ($null -ne $tick); d = '' }
# This profile was wiped before the run, so the window IS a first install: it has just
# minted a number and a key. Everything the mate needs on day one has to be on screen,
# not in a file they will never open - a headless run prints it, a window used to bury it.
$appNumberLine = Text-Containing $hwnd 'This is YOUR app number'
$shareLine = Text-Containing $hwnd 'Tell it to somebody: 700'
# Fall back to the document text, which is where log lines actually live. Whichever of
# the two paths finds it, it was found on the screen - and if BOTH come back empty, the
# report says so rather than quietly passing.
$docText = Doc-Text $hwnd
if ($appNumberLine.Length -eq 0 -and $docText -match 'This is YOUR app number') { $appNumberLine = 'found in the document text' }
if ($shareLine.Length -eq 0 -and $docText -match 'Tell it to somebody: (700 \d{3} \d{4})') { $shareLine = $Matches[1] }
$relayLineOk = (($docText -match 'a relay is needed') -or ((Text-Containing $hwnd 'a relay is needed').Length -gt 0))
"first-run guidance on screen: $appNumberLine / $shareLine (document chars=" + $docText.Length + ")"
$checks += @{ n = 'a first-run window says out loud what number it just gave them'
             ok = ($appNumberLine.Length -gt 0 -and $shareLine -match '700 \d{3} \d{4}')
             d = ('share line: ' + $shareLine) }
$checks += @{ n = '...and tells them a relay is what stands between them and the rest of the world'
             ok = $relayLineOk
             d = $(if ($relayLineOk) { '' } else { 'no relay guidance line on a first run' }) }
$checks += @{ n = 'toggling it on reaches the saved config'
             ok = ($toggledOn -and $cfgOn); d = "toggled=$toggledOn persisted=$cfgOn" }
$checks += @{ n = '...and toggling it off persists false, so the default is not sticky'
             ok = ($toggledOff -and $cfgOff); d = "off=$toggledOff persisted=$cfgOff" }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
''
'--- what the relay saw ---'
((Read-Text $outR) -split "`n" | Where-Object { $_ -match 'SEED LINE|Registered|RELAY STATUS' } | Select-Object -Last 5)
Kill-Leftovers $base
try { Stop-Transcript | Out-Null } catch { }
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if ($allOk) { exit 0 } else { exit 1 }
