# D1b user-path proof: the route table a person can read, and the one consent
# switch that changes what this node is willing to carry.
#
# The selftest already covers the router's arithmetic (13 routing assertions).
# What only a UI test can show is that the table on screen is the router's own
# view, that the tick reaches the router instead of staying decoration, and -
# the part most likely to be lied about - that turning "carry for peers" on does
# NOT make the relay hop claim to carry anyone else's traffic.
#
# It runs in its own temp profile against a stub relay, and cleans up the
# instance and the config it touched.
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$rDir = Join-Path $env:TEMP 'opencode\instR'
$numR = '7003256511'
$port = 45699
$wire = Join-Path $root 'diagnostics\routes_relay.log'
$trace = Join-Path $rDir 'hang_trace.txt'

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Routes {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
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
  [Routes]::pid = $procId; [Routes]::hl.Clear()
  $cb = [Routes+EnumProc] { param($h, $l)
    $o = 0; [Routes]::GetWindowThreadProcessId($h, [ref]$o) | Out-Null
    if ($o -eq [Routes]::pid) { [Routes]::hl.Add($h) }
    return $true }
  [Routes]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
  foreach ($h in [Routes]::hl) {
    $tb = New-Object System.Text.StringBuilder 256
    [Routes]::GetWindowText($h, $tb, 256) | Out-Null
    if ($tb.ToString() -like '*USSD Manager Pro*') { return $h }
  }
  return [IntPtr]::Zero
}
# ControlType members are public static readonly fields, not properties.
function Get-CT([string]$name) {
  $t = [System.Windows.Automation.ControlType]
  $f = $t.GetField($name, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
  if ($f) { return $f.GetValue($null) }
  throw "no ControlType named '$name'"
}
function Names($root, [string]$ctName) {
  $ct = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty, (Get-CT $ctName))
  $out = @()
  foreach ($e in $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $ct)) {
    $out += [string]$e.Current.Name
  }
  return $out
}

$checks = @()
function Add-Check([string]$n, [bool]$ok, [string]$d) { $script:checks += @{ n = $n; ok = $ok; d = $d } }

# --- a profile of its own, on a relay that only has to acknowledge ----------
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Seconds 2
if (-not (Test-Path $rDir)) { New-Item -ItemType Directory -Path $rDir | Out-Null }
foreach ($f in @('identity.key', 'peers_identity.txt', 'ussd_config.json', 'hang_trace.txt', 'wake_agent.log')) {
  Remove-Item -Path (Join-Path $rDir $f) -Force -ErrorAction SilentlyContinue
}
Copy-Item (Join-Path $root 'Csharp\UssdApp.exe') -Destination $rDir -Force
Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $rDir -Force -ErrorAction SilentlyContinue
Set-Content -Path (Join-Path $rDir 'ussd_config.json') -Value ('{
  "mifi_ip": "",
  "com_port": "",
  "baud": "115200",
  "use_serial": false,
  "auto_connect": false,
  "virtual_number": "' + $numR + '",
  "number_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "relay_server": "127.0.0.1:' + $port + '",
  "host_calls": false,
  "theme": "dark",
  "display_name": "RoutesTest",
  "noise_filter": true,
  "record_calls": false,
  "always_awake": false,
  "carry_for_peers": false
}') -Encoding UTF8

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

$env:USSD_FAKE_MIC = '1'
$env:USSD_TRACE = '1'
$ps = Start-Process -FilePath (Join-Path $rDir 'UssdApp.exe') -WorkingDirectory $rDir -PassThru
'hwindow pid=' + $ps.Id

# --- wait for the table and the consent tick to exist -----------------------
$hwnd = [IntPtr]::Zero; $tbl = $null; $chk = $null
$up = (Get-Date).AddSeconds(150)
while ((Get-Date) -lt $up) {
  Poll-Relay
  if ($hwnd -eq [IntPtr]::Zero) { $hwnd = Find-Win $ps.Id }
  if ($hwnd -ne [IntPtr]::Zero -and ($null -eq $tbl -or $null -eq $chk)) {
    try {
      [Routes]::ShowWindow($hwnd, 9) | Out-Null
      $r = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
      $c1 = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, 'Route table')
      $tbl = $r.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c1)
      $c2 = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, 'Carry traffic for other peers')
      $chk = $r.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c2)
    } catch { $tbl = $null; $chk = $null }
  }
  if ($tbl -and $chk) { break }
  Start-Sleep -Milliseconds 500
}
Add-Check 'the dialer shows a route table' ($null -ne $tbl) ('type=' + $(if ($tbl) { $tbl.Current.ControlType.ProgrammaticName } else { 'none' }))
Add-Check 'the table has a consent switch beside it' ($null -ne $chk) ''

$root_ = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
Poll-Relay; Start-Sleep -Seconds 3
$cells = @(Names $root_ 'Text')
'cells: ' + (($cells | Where-Object { $_ -eq 'relay' -or $_ -like 'own traffic*' -or $_ -like 'carries*' -or $_ -eq 'any size' -or $_ -like '*kbps' -or $_ -eq 'unknown' -or $_ -eq 'ready' -or $_ -eq 'down' }) -join ' | ')
Add-Check 'the table lists the link the router registered' ($cells -contains 'relay') ('relay cells=' + @($cells | Where-Object { $_ -eq 'relay' }).Count)
Add-Check 'the relay hop says it carries only your traffic' ($cells -contains 'own traffic only') ''
Add-Check 'nothing claims to carry for peers before being asked' (-not ($cells -contains 'carries for peers')) ''

# --- tick it: the switch has to reach the router and the file --------------
$toggled = $false
if ($chk) {
  $pat = $null
  if ($chk.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pat)) { $pat.Toggle(); $toggled = $true }
}
Start-Sleep -Seconds 3
Poll-Relay
$cfgOn = Read-Text (Join-Path $rDir 'ussd_config.json')
$trOn = Read-Text $trace
$cells2 = @(Names ([System.Windows.Automation.AutomationElement]::FromHandle($hwnd)) 'Text')
Add-Check 'the tick persisted carry_for_peers in the config' ($toggled -and $cfgOn -match '"carry_for_peers":\s*true') ''
Add-Check 'the tick told the router, not just the checkbox' ($trOn -match 'carrying for peers allowed') ((($trOn -split "`n" | Select-String -SimpleMatch 'Route: carrying' | Select-Object -Last 1)))
Add-Check 'turning it on did not make the relay carry for others' ($cells2 -contains 'own traffic only' -and -not ($cells2 -contains 'carries for peers')) ''

# --- untick it: the honest default is restored, on disk and on screen ------
$pat2 = $null
if ($chk -and $chk.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pat2)) { $pat2.Toggle() }
Start-Sleep -Seconds 3
Poll-Relay
$cfgOff = Read-Text (Join-Path $rDir 'ussd_config.json')
$trOff = Read-Text $trace
Add-Check 'unticking persisted carry_for_peers false' ($cfgOff -match '"carry_for_peers":\s*false') ''
Add-Check 'the refusal is stated as plainly as the allowance' ($trOff -match 'carrying for peers refused') ''

# --- refresh is not a no-op: the table survives being rebuilt -------------
$root3 = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
$cb = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::NameProperty, 'Refresh routes')
$rb = $root3.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cb)
$refreshed = 'no button'
if ($rb) {
  try { $rb.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); $refreshed = 'invoked' } catch { $refreshed = 'invoke failed' }
}
Start-Sleep -Seconds 2
$cells3 = @(Names ([System.Windows.Automation.AutomationElement]::FromHandle($hwnd)) 'Text')
Add-Check 'refreshing keeps the same link in the table' ($refreshed -eq 'invoked' -and ($cells3 -contains 'relay')) ('refresh=' + $refreshed)

# --- cleanup --------------------------------------------------------------
try { if (-not $ps.HasExited) { $ps.Kill(); $ps.WaitForExit(8000) | Out-Null } } catch { }
foreach ($c in @($clients)) { try { $c.Tcp.Close() } catch { } }
try { $listener.Stop() } catch { }
$left = @(Get-Process UssdApp -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -eq (Join-Path $rDir 'UssdApp.exe') } catch { $false } })
Add-Check 'the test stopped the instance it started' ($left.Count -eq 0) ('left=' + ($left | ForEach-Object { $_.Id }))

'=== verdict ==='
$allOk = $true
foreach ($c3 in $checks) {
  $s = if ($c3.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c3.n, $c3.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
if (-not $allOk) { exit 1 }
exit 0
