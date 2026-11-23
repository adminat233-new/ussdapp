# C1 user-path proof: tick "Always awake", close the window, and a headless
# listener really takes the relay slot over.
#
# Everything else about the agent is covered by agent_e2e.ps1. What this file
# tests is the part a person touches: the checkbox, the setting it writes, the
# sign-in registration, and the hand-off on exit. It cleans up after itself,
# including the HKCU Run entry it creates - a test must not leave the user's
# machine starting a temp-folder exe at every logon.
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$gDir = Join-Path $env:TEMP 'opencode\instG'
$numG = '7003256433'
$port = 45693
$wire = Join-Path $root 'diagnostics\wake_relay.log'
$trace = Join-Path $gDir 'hang_trace.txt'
$runKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$runValue = 'UssdWakeAgent'

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Wake {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  public static int pid;
  public static System.Collections.Generic.List<IntPtr> hl = new System.Collections.Generic.List<IntPtr>();
}
"@

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}
function Find-Win([int]$procId) {
  [Wake]::pid = $procId; [Wake]::hl.Clear()
  $cb = [Wake+EnumProc] { param($h, $l)
    $o = 0; [Wake]::GetWindowThreadProcessId($h, [ref]$o) | Out-Null
    if ($o -eq [Wake]::pid) { [Wake]::hl.Add($h) }
    return $true }
  [Wake]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
  foreach ($h in [Wake]::hl) {
    $tb = New-Object System.Text.StringBuilder 256
    [Wake]::GetWindowText($h, $tb, 256) | Out-Null
    if ($tb.ToString() -like '*USSD Manager Pro*') { return $h }
  }
  return [IntPtr]::Zero
}

# --- clean slate ------------------------------------------------------------
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
try { Remove-ItemProperty -Path ('HKCU:\' + $runKey) -Name $runValue -ErrorAction SilentlyContinue } catch { }
Start-Sleep -Seconds 2
if (-not (Test-Path $gDir)) { New-Item -ItemType Directory -Path $gDir | Out-Null }
foreach ($f in @('identity.key', 'peers_identity.txt', 'ussd_config.json', 'hang_trace.txt', 'startup.log', 'wake_agent.log')) {
  Remove-Item -Path (Join-Path $gDir $f) -Force -ErrorAction SilentlyContinue
}
Remove-Item -Path (Join-Path $gDir 'chats') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $gDir 'wake_inbox') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root 'Csharp\UssdApp.exe') -Destination $gDir -Force
Copy-Item (Join-Path $root 'Csharp\UssdAgent.exe') -Destination $gDir -Force
Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $gDir -Force -ErrorAction SilentlyContinue
# A profile with the relay configured and the listener off: that is the state a
# new install is in, and the only thing the test should change is the checkbox.
Set-Content -Path (Join-Path $gDir 'ussd_config.json') -Value ('{
  "mifi_ip": "",
  "com_port": "",
  "baud": "115200",
  "use_serial": false,
  "auto_connect": false,
  "virtual_number": "' + $numG + '",
  "number_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "relay_server": "127.0.0.1:' + $port + '",
  "host_calls": false,
  "theme": "dark",
  "display_name": "WakeTest",
  "noise_filter": true,
  "record_calls": false,
  "always_awake": false
}') -Encoding UTF8

# --- a relay that only has to acknowledge the registration ------------------
Set-Content -Path $wire -Value ('=== relay on 127.0.0.1:' + $port + ' ' + (Get-Date -Format 'o'))
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
$listener.Start()
$clients = New-Object System.Collections.ArrayList
function Wire([string]$s) { Add-Content -Path $wire -Value ((Get-Date -Format 'HH:mm:ss.fff') + ' ' + $s) }
function Poll-Relay {
  if ($listener.Pending()) {
    $tc = $listener.AcceptTcpClient()
    [void]$clients.Add([pscustomobject]@{ Tcp = $tc; Stream = $tc.GetStream(); Pending = '' })
    Wire ('+ connection ' + $tc.Client.RemoteEndPoint)
  }
  foreach ($c in @($clients)) {
    try {
      while ($c.Stream.DataAvailable) {
        $buf = New-Object byte[] 8192
        $n = $c.Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { Wire ('- closed'); [void]$clients.Remove($c); break }
        $c.Pending += [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
        while ($c.Pending.Contains("`n")) {
          $i = $c.Pending.IndexOf("`n")
          $ln = $c.Pending.Substring(0, $i).TrimEnd("`r").TrimStart([char]0xFEFF)
          $c.Pending = $c.Pending.Substring($i + 1)
          Wire ('<- ' + $ln.Substring(0, [Math]::Min(90, $ln.Length)))
          $p = $ln -split '\|', 4
          if ($p[0] -eq 'REG') {
            $b = [System.Text.Encoding]::UTF8.GetBytes('OK|' + $p[1] + "`n")
            try { $c.Stream.Write($b, 0, $b.Length) } catch { }
          }
        }
      }
    } catch { [void]$clients.Remove($c) }
  }
}

# --- open the window --------------------------------------------------------
$env:USSD_FAKE_MIC = '1'
$env:USSD_TRACE = '1'
$ps = Start-Process -FilePath (Join-Path $gDir 'UssdApp.exe') -WorkingDirectory $gDir -PassThru
'hwindow pid=' + $ps.Id
$hwnd = [IntPtr]::Zero
$up = (Get-Date).AddSeconds(120)
$chk = $null
while ((Get-Date) -lt $up) {
  Poll-Relay
  if ($hwnd -eq [IntPtr]::Zero) { $hwnd = Find-Win $ps.Id }
  if ($hwnd -ne [IntPtr]::Zero -and -not $chk) {
    try {
      [Wake]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE: the harness desktop may minimize it
      $r = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
      $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, 'Always awake')
      $chk = $r.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    } catch { $chk = $null }
  }
  if ($chk) { break }
  Start-Sleep -Milliseconds 400
}
if (-not $chk) { 'FAIL: the Always awake checkbox was never found in the UI' }
else { 'found the checkbox: "' + [string]$chk.Current.Name + '" offscreen=' + $chk.Current.IsOffscreen }

$checks = @()
$checks += @{ n = 'the window shows an Always awake control'; ok = ($null -ne $chk); d = '' }

# --- tick it ----------------------------------------------------------------
$toggled = $false
if ($chk) {
  $pat = $null
  if ($chk.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pat)) {
    $pat.Toggle(); $toggled = $true
  }
}
Start-Sleep -Seconds 3
Poll-Relay
$cfgAfter = Read-Text (Join-Path $gDir 'ussd_config.json')
$reg = $null
try { $reg = (Get-ItemProperty -Path ('HKCU:\' + $runKey) -ErrorAction Stop).$runValue } catch { $reg = $null }
$checks += @{ n = 'the tick persisted always_awake in the config'; ok = ($toggled -and $cfgAfter -match '"always_awake":\s*true'); d = '' }
$checks += @{ n = 'the tick registered the listener at sign-in'; ok = ($reg -and $reg -match '--agent' -and $reg -match [regex]::Escape($gDir)); d = 'run=' + $reg }
'trace of the toggle: ' + (((Read-Text $trace) -split "`n" | Select-String -SimpleMatch 'Wake agent' | Select-Object -Last 2) -join ' | ')

# --- close the window for real (the first close only goes to the tray) ------
# Process.CloseMainWindow stops working once the app hides itself: there is no
# main window handle any more, so it silently does nothing. WM_CLOSE posted to
# the HWND is what the tray's Exit item ends up doing, and it reaches a hidden
# WPF window fine.
if ($hwnd -ne [IntPtr]::Zero) {
  [Wake]::PostMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null   # WM_CLOSE -> tray
  Start-Sleep -Seconds 4
  Poll-Relay
  [Wake]::PostMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null   # WM_CLOSE -> exit
  Poll-Relay
}
$agentPid = 0
$agentSeenAt = $null
$gone = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $gone) {
  Poll-Relay
  $a = @(Get-Process UssdAgent -ErrorAction SilentlyContinue | Where-Object {
      try { $_.Path -eq (Join-Path $gDir 'UssdAgent.exe') } catch { $false } })
  if ($a.Count -gt 0) { $agentPid = $a[0].Id; $agentSeenAt = Get-Date; break }
  Start-Sleep -Milliseconds 250
}
$agentCmd = ''
if ($agentPid) {
  try { $agentCmd = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $agentPid)).CommandLine } catch { }
}
$windowStillUp = @(Get-Process UssdApp -ErrorAction SilentlyContinue | Where-Object { try { $_.Id -eq $ps.Id } catch { $false } }).Count -gt 0
# A started process is not a listener. The only thing that proves the hand-off
# worked is this number appearing on the wire again, from the agent, after the
# window's socket went away - so wait for the second REG rather than assuming it.
$regLines = ([regex]::Matches((Read-Text $wire), [regex]::Escape('REG|' + $numG))).Count
$regAt = $null
$wireDeadline = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $wireDeadline) {
  Poll-Relay
  $regLines = ([regex]::Matches((Read-Text $wire), [regex]::Escape('REG|' + $numG))).Count
  if ($regLines -ge 2) { $regAt = Get-Date; break }
  Start-Sleep -Milliseconds 250
}
$checks += @{ n = 'exiting the window started the listener'; ok = ($agentPid -ne 0); d = 'pid=' + $agentPid }
# The listener is launched with no console, so its own log file is the only word
# from it. Checking that file is what distinguishes "registered" from "connected
# and then lost the slot" in the wire log.
$agentLog = Read-Text (Join-Path $gDir 'wake_agent.log')
$checks += @{ n = 'the listener left a readable log of itself'; ok = ($agentLog -match 'AGENT number=' + $numG + ' .*connected=True'); d = (($agentLog -split "`n" | Select-String -SimpleMatch 'AGENT ' | Select-Object -First 2) -join ' | ') }
$checks += @{ n = 'the listener was handed this profile, number and relay'; ok = ($agentCmd -match '--agent' -and $agentCmd -match [regex]::Escape($gDir) -and $agentCmd -match $numG -and $agentCmd -match ('--relay=127.0.0.1:' + $port)); d = $agentCmd }
$checks += @{ n = 'the listener registered on the relay'; ok = ($regLines -ge 2); d = 'REG lines=' + $regLines + ' within ' + $(if ($regAt -and $agentSeenAt) { [int]($regAt - $agentSeenAt).TotalSeconds } else { '>' + 44 }) + ' s of it starting' }
$checks += @{ n = 'the window is gone, so nothing is fighting for the slot'; ok = (-not $windowStillUp); d = 'windowUp=' + $windowStillUp }

# --- cleanup: no temp exe may survive into the user's sign-in --------------
Get-Process UssdAgent -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch { } }
try { Remove-ItemProperty -Path ('HKCU:\' + $runKey) -Name $runValue -Force -ErrorAction SilentlyContinue } catch { }
foreach ($c in @($clients)) { try { $c.Tcp.Close() } catch { } }
try { $listener.Stop() } catch { }
$regFinal = $null
try { $regFinal = (Get-ItemProperty -Path ('HKCU:\' + $runKey) -ErrorAction Stop).$runValue } catch { $regFinal = $null }
$checks += @{ n = 'the test left no sign-in entry behind'; ok = ($null -eq $regFinal); d = 'still=' + $regFinal }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if (-not $allOk) { exit 1 }
exit 0
