# Hub (3-pane chat) end-to-end driver: UI Automation + window screenshots.
# Phases: up, open:<A|B>, send:<A|B>, killb, startb, vn:<B|A>, play:<A|B>,
#         search:<A|B>, export:<A|B>, delete:<A|B>, resize:<A|B>, logs, rows:<A|B>
param(
  [Parameter(Mandatory = $true)][string]$Phase,
  [string]$Text = 'hub e2e message',
  [string]$Query = 'voice',
  [int]$Secs = 6,
  [int]$W = 900,
  [int]$H = 700,
  [int]$Tail = 25
)
$ErrorActionPreference = 'SilentlyContinue'
$Work = 'C:\Users\Admin\Documents\Default Project\ussdApp\Csharp'
$Bdir = Join-Path $env:TEMP 'opencode\instB'
$PidFile = Join-Path $env:TEMP 'opencode\callpids.txt'
$OutDir = Join-Path $env:TEMP 'opencode'

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Hub {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  public static int pid;
  public static System.Collections.Generic.List<IntPtr> hl = new System.Collections.Generic.List<IntPtr>();
  public static void Click(int x, int y) {
    SetCursorPos(x, y); System.Threading.Thread.Sleep(120);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
  }
  public static void RightClick(int x, int y) {
    SetCursorPos(x, y); System.Threading.Thread.Sleep(120);
    mouse_event(0x0008,0,0,0,UIntPtr.Zero); mouse_event(0x0010,0,0,0,UIntPtr.Zero);
  }
}
"@
[Hub]::SetProcessDPIAware() | Out-Null

function Dir-For([string]$k) { if ($k -eq 'B') { return $Bdir } else { return $Work } }

# The app's own log is the only honest way to know a conversation is open and a
# message actually left: the composer exists even with no recipient selected.
function Trace-Has([string]$k, [string]$needle, [int]$tail) {
  $p = Join-Path (Dir-For $k) 'hang_trace.txt'
  if (-not (Test-Path $p)) { return '' }
  foreach ($l in (@(Get-Content $p -Tail $tail) | ForEach-Object { $_.Trim() })) {
    if ($l -like ('*' + $needle + '*')) { return $l }
  }
  return ''
}

# Drive nav -> category -> conversation row until the chat composer is really on
# screen AND the app itself says a conversation was opened, so a layout
# measurement can never be taken from the wrong workspace and a send can never
# be reported as done when the app refused it for lack of a recipient.
function Ensure-Chat($app, [string]$key) {
  for ($try = 0; $try -lt 4; $try++) {
    [void](Invoke-Btn $app.Root 'SMS' 'suffix'); Start-Sleep -Seconds 2
    [void](Invoke-Btn $app.Root 'SMS msgs' 'exact'); Start-Sleep -Seconds 2
    $row = Open-FirstRow $app ''; Start-Sleep -Seconds 2
    $app.Root = [System.Windows.Automation.AutomationElement]::FromHandle($app.Hwnd)
    $composer = $false
    foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Edit))) {
      if ([string]$e.Current.Name -ceq 'Chat message' -and -not $e.Current.IsOffscreen) { $composer = $true; break }
    }
    $opened = Trace-Has $key 'Chat: opened #' 60
    if ($composer -and $opened.Length -gt 0) {
      return 'chat ready (try ' + ($try + 1) + ', ' + $row + '; ' + $opened.Substring($opened.IndexOf('Chat:')) + ')'
    }
  }
  return 'chat NEVER became visible'
}

function Read-Pids {
  $h = @{}
  if (Test-Path $PidFile) {
    foreach ($line in (Get-Content $PidFile)) { $p = $line -split '=', 2; if ($p.Count -eq 2) { $h[$p[0]] = [int]$p[1] } }
  }
  return $h
}

function Find-Win([int]$procId) {
  [Hub]::pid = $procId; [Hub]::hl.Clear()
  $cb = [Hub+EnumProc] { param($h, $l)
    $o = 0; [Hub]::GetWindowThreadProcessId($h, [ref]$o) | Out-Null
    if ($o -eq [Hub]::pid) { [Hub]::hl.Add($h) }
    return $true }
  [Hub]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
  foreach ($h in [Hub]::hl) {
    $tb = New-Object System.Text.StringBuilder 256
    [Hub]::GetWindowText($h, $tb, 256) | Out-Null
    if ($tb.ToString() -like '*USSD Manager Pro*') { return $h }
  }
  return [IntPtr]::Zero
}

# Restore the window (the app lives in the tray and the desktop may minimize it)
# and hand back the automation root plus the DPI factor for mouse coordinates.
function Open-App([string]$k) {
  $map = Read-Pids
  if (-not $map.ContainsKey($k)) { throw "no pid for $k" }
  $hwnd = Find-Win $map[$k]
  if ($hwnd -eq [IntPtr]::Zero) { throw "no window for $k" }
  # Only restore a genuinely minimised window: SW_RESTORE on an already-visible
  # window would snap it back to its normal bounds and undo any test resize.
  # A window hidden to the tray is not iconic, so it needs SW_SHOW (5) to make
  # the automation tree report real coordinates instead of the -31154 sentinel.
  if ([Hub]::IsIconic($hwnd)) {
    for ($i = 0; $i -lt 10 -and [Hub]::IsIconic($hwnd); $i++) {
      [Hub]::ShowWindow($hwnd, 9) | Out-Null
      Start-Sleep -Milliseconds 250
    }
  } else {
    [Hub]::ShowWindow($hwnd, 5) | Out-Null
    Start-Sleep -Milliseconds 400
  }
  [Hub]::SetForegroundWindow($hwnd) | Out-Null
  Start-Sleep -Milliseconds 700
  $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
  $wr = New-Object Hub+RECT
  [Hub]::GetWindowRect($hwnd, [ref]$wr) | Out-Null
  $scale = 1.0
  $lr = $root.Current.BoundingRectangle
  if ($lr.Width -gt 0) { $scale = ($wr.R - $wr.L) / $lr.Width }
  return [pscustomobject]@{ Hwnd = $hwnd; Root = $root; Scale = $scale; Pid = $map[$k] }
}

# Re-read the automation tree after a geometry change (no show/restore side effects).
function Refresh-Root($app) {
  Start-Sleep -Milliseconds 900
  $r = [System.Windows.Automation.AutomationElement]::FromHandle($app.Hwnd)
  $wr = New-Object Hub+RECT
  [Hub]::GetWindowRect($app.Hwnd, [ref]$wr) | Out-Null
  $scale = $app.Scale
  $lr = $r.Current.BoundingRectangle
  if ($lr.Width -gt 0) { $scale = ($wr.R - $wr.L) / $lr.Width }
  $app.Root = $r
  $app.Scale = $scale
  return $wr
}

function Get-ByType($root, $ctype) {
  $ct = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ctype)
  return $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $ct)
}

function Invoke-Btn($root, [string]$want, [string]$mode) {
  foreach ($e in (Get-ByType $root ([System.Windows.Automation.ControlType]::Button))) {
    $n = [string]$e.Current.Name
    $hit = $false
    if ($mode -eq 'suffix') { if ($n -like ("*" + $want)) { $hit = $true } } elseif ($mode -eq 'prefix') { if ($n -like ($want + "*")) { $hit = $true } } else { if ($n -ceq $want) { $hit = $true } }
    if ($hit) {
      try { $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); return "invoked '$n'" } catch { return "invoke failed '$n'" }
    }
  }
  return "MISSING button '$want'"
}

function Set-Edit($root, [string]$want, [string]$value) {
  foreach ($e in (Get-ByType $root ([System.Windows.Automation.ControlType]::Edit))) {
    if ([string]$e.Current.Name -ceq $want) {
      try { $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($value); return "set '$want' = " + $value } catch { return "set failed '$want'" }
    }
  }
  return "MISSING edit '$want'"
}

function Shot($app, [string]$name) {
  $hwnd = $app.Hwnd
  if ([Hub]::IsIconic($hwnd)) { [Hub]::ShowWindow($hwnd, 9) | Out-Null; Start-Sleep -Milliseconds 350 }
  $r = New-Object Hub+RECT
  [Hub]::GetWindowRect($hwnd, [ref]$r) | Out-Null
  $w = $r.R - $r.L; $h = $r.B - $r.T
  if ($w -le 0) { return 'bad rect' }
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc()
  [Hub]::PrintWindow($hwnd, $hdc, 2) | Out-Null
  $g.ReleaseHdc($hdc); $g.Dispose()
  $out = Join-Path $OutDir ($name + '.png')
  $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  return "saved $out"
}

function ShotHwnd($hwnd, [string]$name) {
  $r = New-Object Hub+RECT
  [Hub]::GetWindowRect($hwnd, [ref]$r) | Out-Null
  $w = $r.R - $r.L; $h = $r.B - $r.T
  if ($w -le 0) { return 'bad rect' }
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc()
  [Hub]::PrintWindow([IntPtr]$hwnd, $hdc, 2) | Out-Null
  $g.ReleaseHdc($hdc); $g.Dispose()
  $out = Join-Path $OutDir ($name + '.png')
  $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  return "saved $out ($w x $h)"
}

# Every conversation / peer row is a Button named "Open chat with <name> (<num>)".
function Open-FirstRow($app, [string]$needle) {
  $r = (Invoke-Btn $app.Root ("Open chat with " + $needle) 'prefix')
  if ($r -like 'invoked*') { return $r }
  # fall back to the very first row of the list
  foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
    $n = [string]$e.Current.Name
    if ($n -like 'Open chat with*') {
      try { $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); return "invoked '$n'" } catch { }
    }
  }
  return "MISSING row '$needle'"
}

function List-Rows($app) {
  $out = @()
  foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
    $n = [string]$e.Current.Name
    if ($n -like 'Open chat with*') { $out += "ROW [$n]" }
  }
  if ($out.Count -eq 0) { $out += 'ROW none' }
  return $out
}

# Texts inside pane 3 (message bubbles) - used to verify what the user sees.
function List-Bubbles($app) {
  $out = @()
  foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Text))) {
    $n = [string]$e.Current.Name
    $r = $e.Current.BoundingRectangle
    if ($n.Length -eq 0 -or $r.Width -le 0 -or $app.Scale -le 0) { continue }
    $x = $r.X * $app.Scale
    if ($x -gt 620) { $out += ("BUB [$n] y=" + [int]($r.Y * $app.Scale)) }
  }
  return $out
}

function MicState($app) {
  $out = @()
  foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
    $n = [string]$e.Current.Name
    if ($n -eq 'Record' -or $n -like 'Stop*') {
      $r = $e.Current.BoundingRectangle
      $h = ''
      try { $h = $e.Current.HelpText } catch { }
      $out += ("MIC [$n] off=" + $e.Current.IsOffscreen + " " + [int]($r.X * $app.Scale) + "," + [int]($r.Y * $app.Scale) + " help=" + $h)
    }
  }
  if ($out.Count -eq 0) { $out += 'MIC MISSING' }
  return $out
}

function Chat-Counts([string]$dir) {
  if (-not (Test-Path $dir)) { return @('no chats dir ' + $dir) }
  $out = @()
  foreach ($f in (Get-ChildItem -Path $dir -Filter '*.txt')) {
    $out += ($f.Name + '=' + (Get-Content $f.FullName | Measure-Object -Line).Lines)
  }
  if ($out.Count -eq 0) { $out += 'no chat files' }
  return $out
}

function Last-Log([string]$exe, [string]$pattern, [int]$n) {
  $p = Join-Path (Split-Path $exe) 'hang_trace.txt'
  if (-not (Test-Path $p)) { return @('no trace ' + $p) }
  $lines = Get-Content $p -Tail 400 | Select-String -SimpleMatch $pattern
  if (-not $lines) { return @("no log line '$pattern'") }
  return @($lines | Select-Object -Last $n | ForEach-Object { $_.Line.Trim() })
}

function Wait-Win([int]$procId, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $w = Find-Win $procId
    if ($w -ne [IntPtr]::Zero) { return $w }
    Start-Sleep -Milliseconds 500
  }
  return [IntPtr]::Zero
}

# A named element from the automation tree, on any control type. The security
# sheet labels every piece of it, so a test can read what a person reads.
# ControlType members are public static readonly FIELDS ('Text' is a field, not
# a property): GetProperty returns null for them, which silently matched nothing
# and made every text read look like an empty screen. Fields first, property as
# a fallback, and a loud throw if neither exists - a helper that returns null is
# worse than one that fails.
function Resolve-CT([string]$name) {
  $t = [System.Windows.Automation.ControlType]
  $f = $t.GetField($name, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
  if ($f) { return $f.GetValue($null) }
  $p = $t.GetProperty($name, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
  if ($p) { return $p.GetValue($null) }
  throw "no ControlType named '$name'"
}
function Find-Named($root, [string]$want, [string]$ctName, [int]$tries) {
  $ct = Resolve-CT $ctName
  for ($try = 0; $try -lt $tries; $try++) {
    foreach ($e in (Get-ByType $root $ct)) {
      if ([string]$e.Current.Name -ceq $want) { return $e }
    }
    Start-Sleep -Milliseconds 400
  }
  return $null
}
function Name-Of($root, [string]$want, [string]$ctName) {
  $e = Find-Named $root $want $ctName 1
  if ($e) { return [string]$e.Current.Name }
  return ''
}
# Value lines carry their own label in their text, so searching by prefix reads
# exactly what is on screen.
function Get-PrefixText($root, [string]$prefix, [int]$tries) {
  $ct = Resolve-CT 'Text'
  for ($t = 0; $t -lt $tries; $t++) {
    foreach ($e in (Get-ByType $root $ct)) {
      $n = [string]$e.Current.Name
      if ($n.StartsWith($prefix)) { return $n }
    }
    Start-Sleep -Milliseconds 400
  }
  return ''
}
function Test-Button($root, [string]$want) {
  $e = Find-Named $root $want 'Button' 1
  if ($e) { return [string]$e.Current.IsOffscreen }
  return 'absent'
}

$map = Read-Pids

switch -Wildcard ($Phase) {

  'up' {
    & pwsh -NoProfile -File (Join-Path $OutDir 'calltest.ps1') -Phase setup 2>&1 | Select-Object -Last 6
    exit 0
  }

  'down' {
    # Stop every instance so build.bat can overwrite the exe. Doing this inside
    # the script keeps the outer command a plain script invocation.
    & taskkill /F /IM UssdApp.exe 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    'stopped; remaining=' + ((Get-Process UssdApp -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) -join ',')
    exit 0
  }

  'relaunch' {
    # Restart both instances on the freshly built exe, keeping existing chat
    # history, and enable the synthetic mic so voice notes work without a device.
    & taskkill /F /IM UssdApp.exe | Out-Null
    Start-Sleep -Seconds 2
    Copy-Item -Path (Join-Path $Work 'UssdApp.exe') -Destination $Bdir -Force
    Copy-Item -Path (Join-Path $Work 'UssdApp.ico') -Destination $Bdir -Force
    $env:USSD_FAKE_MIC = '1'
    $trace = Join-Path $Work 'hang_trace.txt'
    $before = 0
    if (Test-Path $trace) { $before = (Get-Item $trace).Length }
    $pa = Start-Process -FilePath (Join-Path $Work 'UssdApp.exe') -PassThru
    $deadline = (Get-Date).AddSeconds(60)
    $bound = $false
    while ((Get-Date) -lt $deadline -and -not $bound) {
      Start-Sleep -Milliseconds 800
      if (Test-Path $trace) {
        $fs = [System.IO.File]::Open($trace, 'Open', 'Read', 'ReadWrite')
        $fs.Position = [Math]::Min($before, $fs.Length)
        $sr = New-Object System.IO.StreamReader($fs)
        $newText = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        if ($newText -match 'VoIP started') { $bound = $true }
      }
    }
    'A bound=' + $bound + ' pid=' + $pa.Id
    $pb = Start-Process -FilePath (Join-Path $Bdir 'UssdApp.exe') -PassThru
    "A=$($pa.Id)" | Set-Content $PidFile
    "B=$($pb.Id)" | Add-Content $PidFile
    [void](Wait-Win $pa.Id 90)
    [void](Wait-Win $pb.Id 90)
    Start-Sleep -Seconds 8
    'relaunched A=' + $pa.Id + ' B=' + $pb.Id
    exit 0
  }

  'killb' {
    if ($map.ContainsKey('B')) { & taskkill /F /PID $map['B'] | Out-Null }
    Start-Sleep -Seconds 2
    'B killed'
    exit 0
  }

  'startb' {
    $pb = Start-Process -FilePath (Join-Path $Bdir 'UssdApp.exe') -PassThru
    (Get-Content $PidFile | Where-Object { $_ -notlike 'B=*' }) | Set-Content $PidFile
    "B=$($pb.Id)" | Add-Content $PidFile
    'B started pid=' + $pb.Id
    $w = Wait-Win $pb.Id 60
    if ($w -eq [IntPtr]::Zero) { 'B window never appeared'; exit 1 }
    'B window ready'
    Start-Sleep -Seconds 6
    exit 0
  }

  'peeropen:*' {
    # First contact: open a chat from the online-peer list (no history needed).
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'Peers' 'exact')
    Start-Sleep -Seconds 3
    List-Rows $app
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    'dpi=' + $app.Scale
    MicState $app
    Shot $app ("peeropen_" + $k)
    exit 0
  }

  'rows:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'dpi=' + $app.Scale
    (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    List-Rows $app
    Shot $app ("rows_" + $k)
    exit 0
  }

  'open:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    MicState $app
    Shot $app ("open_" + $k)
    exit 0
  }

  'send:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    # The composer only exists on the chat workspace; navigating first keeps
    # this phase honest instead of silently "sending" into another page.
    'ensure: ' + (Ensure-Chat $app $k)
    'msg: ' + (Set-Edit $app.Root 'Chat message' $Text)
    Start-Sleep -Milliseconds 600
    'send: ' + (Invoke-Btn $app.Root 'Send' 'exact')
    Start-Sleep -Seconds 4
    # Ask the app what it actually did instead of trusting the click.
    $ok = Trace-Has $k ('Chat sent to') 120
    $no = Trace-Has $k ('Chat: enter a recipient number') 120
    $sec = Trace-Has $k ('Security: ') 400
    if ($ok.Length -gt 0) { 'OUTCOME: ' + $ok.Substring($ok.IndexOf('Chat')) } else { 'OUTCOME: nothing was sent' }
    if ($no.Length -gt 0) { 'REFUSED: ' + $no.Substring($no.IndexOf('Chat')) }
    if ($sec.Length -gt 0) { 'SECURITY: ' + $sec.Substring($sec.IndexOf('Security')) }
    Shot $app ("send_" + $k)
    exit 0
  }

  # A3: open the in-chat security sheet and print what it says. Nothing is
  # inferred from files here - these are the strings a person would read out.
  'sec:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'ensure: ' + (Ensure-Chat $app $k)
    $chip = $null
    foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
      if ([string]$e.Current.Name -like 'Chat encryption*') { $chip = $e; break }
    }
    if (-not $chip) { 'CHIP=missing'; exit 1 }
    'CHIP=' + [string]$chip.Current.Name
    try { $chip.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
    catch { 'CHIP invoke failed: ' + $_.Exception.Message }
    Start-Sleep -Seconds 2
    $app.Root = [System.Windows.Automation.AutomationElement]::FromHandle($app.Hwnd)
    'SN=' + (Get-PrefixText $app.Root 'Safety number' 12)
    'MINE=' + (Get-PrefixText $app.Root 'Your key:' 1)
    'PEER=' + (Get-PrefixText $app.Root 'Their key:' 1)
    'DIGEST=' + (Get-PrefixText $app.Root 'safety ' 1)
    'TRUST_offscreen=' + (Test-Button $app.Root 'Trust this new key')
    'COPY_offscreen=' + (Test-Button $app.Root 'Copy safety number')
    'CLOSE_offscreen=' + (Test-Button $app.Root 'Close security details')
    Shot $app ('sec_' + $k)
    exit 0
  }

  # Debug aid for the sheet itself: dump every Text and Button the window exposes,
  # before and after pressing the chip. Used to find out whether the sheet is
  # missing from the tree, present but offscreen, or present under another name.
  'secdump:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'ensure: ' + (Ensure-Chat $app $k)
    $chip = $null
    foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
      if ([string]$e.Current.Name -like 'Chat encryption*') { $chip = $e; break }
    }
    'CHIP=' + [string]$chip.Current.Name
    '--- before ---'
    foreach ($t in (Get-ByType $app.Root (Resolve-CT 'Text'))) {
      'TXT|' + $t.Current.IsOffscreen + '|' + (([string]$t.Current.Name) -replace "`r?`n", ' / ').Substring(0, [Math]::Min(78, ([string]$t.Current.Name).Length))
    }
    try { $chip.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() } catch { 'INVOKE_FAIL ' + $_.Exception.Message }
    Start-Sleep -Seconds 2
    $app.Root = [System.Windows.Automation.AutomationElement]::FromHandle($app.Hwnd)
    '--- after ---'
    foreach ($t in (Get-ByType $app.Root (Resolve-CT 'Text'))) {
      'TXT|' + $t.Current.IsOffscreen + '|' + (([string]$t.Current.Name) -replace "`r?`n", ' / ').Substring(0, [Math]::Min(78, ([string]$t.Current.Name).Length))
    }
    foreach ($b in (Get-ByType $app.Root (Resolve-CT 'Button'))) {
      'BTN|' + $b.Current.IsOffscreen + '|' + [string]$b.Current.Name
    }
    exit 0
  }

  # Read the chip and press nothing else. The TOFU leg has to wait for the
  # blocked state, and a wait that clicks ("ensure the chat") can change the
  # very state it is watching.
  'chip:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    $chip = ''
    foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
      if ([string]$e.Current.Name -like 'Chat encryption*') { $chip = [string]$e.Current.Name; break }
    }
    'CHIP=' + $chip
    # If nothing matched, say what the window did expose: an empty value alone
    # cannot tell "wrong page" from "no window" from "the name changed".
    if ($chip -eq '') {
      $bn = @(Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))
      'BTNS=' + $bn.Count
      'FIRST=' + (($bn | Select-Object -First 6 | ForEach-Object { [string]$_.Current.Name }) -join ';')
    }
    exit 0
  }

  'secclose:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'close: ' + (Invoke-Btn $app.Root 'Close security details' 'exact')
    Start-Sleep -Seconds 1
    $app.Root = [System.Windows.Automation.AutomationElement]::FromHandle($app.Hwnd)
    'SN_still=' + (Get-PrefixText $app.Root 'Safety number' 1)
    exit 0
  }

  'sectrust:*' {
    # The only way out of a blocked key: an explicit press on the warning.
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'trust: ' + (Invoke-Btn $app.Root 'Trust this new key' 'exact')
    Start-Sleep -Seconds 3
    'log: ' + (Last-Log (Join-Path (Dir-For $k) 'UssdApp.exe') 'Security: you accepted' 1)
    exit 0
  }

  # Open the conversation without sending anything: a warning has to be on
  # screen before the event that raises it, not after.
  'chatopen:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'ensure: ' + (Ensure-Chat $app $k)
    $chip = ''
    foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button))) {
      if ([string]$e.Current.Name -like 'Chat encryption*') { $chip = [string]$e.Current.Name; break }
    }
    'CHIP=' + $chip
    exit 0
  }

  'vn:*' {
    # Record a voice note from the given instance (chat must be open).
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    'before:' ; MicState $app
    'rec: ' + (Invoke-Btn $app.Root 'Record' 'exact')
    Start-Sleep -Seconds 3
    'recording:' ; MicState $app
    Shot $app ("vn_" + $k + "_rec")
    Start-Sleep -Seconds $Secs
    'stop: ' + (Invoke-Btn $app.Root 'Stop' 'suffix')
    Start-Sleep -Milliseconds 800
    'after:' ; MicState $app
    Start-Sleep -Seconds 3
    Shot $app ("vn_" + $k + "_sent")
    exit 0
  }

  'play:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    List-Bubbles $app
    'play: ' + (Invoke-Btn $app.Root 'Play voice note' 'exact')
    Start-Sleep -Seconds 2
    Shot $app ("play_" + $k)
    exit 0
  }

  'search:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    'all bubbles:'
    List-Bubbles $app
    'filter: ' + (Set-Edit $app.Root 'Search messages' $Query)
    Start-Sleep -Seconds 2
    'filtered bubbles:'
    List-Bubbles $app
    'rows after filter:'
    List-Rows $app
    Shot $app ("search_" + $k)
    'clear: ' + (Set-Edit $app.Root 'Search messages' '')
    Start-Sleep -Seconds 2
    'after clear:'
    List-Bubbles $app
    exit 0
  }

  'export:*' {
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    'export: ' + (Invoke-Btn $app.Root 'Export chat' 'exact')
    Start-Sleep -Seconds 3
    Shot $app ("export_" + $k)
    exit 0
  }

  'delete:*' {
    # Every bubble carries an invokable "Delete message" button, so the test
    # does not depend on right-click coordinates of a possibly minimised window.
    # Deletion also rewrites the persisted transcript, so verify both.
    $k = $Phase.Split(':')[1]
    $cdir = if ($k -eq 'B') { Join-Path $Bdir 'chats' } else { Join-Path $Work 'chats' }
    $exe = if ($k -eq 'B') { Join-Path $Bdir 'UssdApp.exe' } else { Join-Path $Work 'UssdApp.exe' }
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    $btns = Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button)
    $n = $btns.Count
    $before = 0
    $victim = $null
    for ($i = 0; $i -lt $n; $i++) {
      $e = $btns.Item($i)
      if ([string]$e.Current.Name -ceq 'Delete message') { $before++; $victim = $e }
    }
    'delete buttons before: ' + $before
    'chat files before: ' + ((Chat-Counts $cdir) -join ' ')
    if ($victim -eq $null) { 'no Delete message button'; exit 1 }
    try { $victim.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); 'invoked Delete message' } catch { 'invoke failed: ' + $_.Exception.Message }
    Start-Sleep -Seconds 3
    $btns2 = Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Button)
    $after = 0
    for ($i = 0; $i -lt $btns2.Count; $i++) {
      if ([string]$btns2.Item($i).Current.Name -ceq 'Delete message') { $after++ }
    }
    'delete buttons after: ' + $after
    'chat files after: ' + ((Chat-Counts $cdir) -join ' ')
    'log: ' + ((Last-Log $exe 'message deleted' 1) -join ' ')
    Shot $app ("delete_" + $k + "_done")
    exit 0
  }

  'layout:*' {
    # One clean measurement per window size: restore, resize, re-read a fresh
    # UIA root, then confirm the mic button + composer are inside the window and
    # the newest bubble sits above the composer (auto-scroll pinned to bottom).
    $k = $Phase.Split(':')[1]
    foreach ($size in @(@(1250, 990), [int[]]@($W, $H))) {
      $app = Open-App $k
      'ensure: ' + (Ensure-Chat $app $k)
      [Hub]::SetWindowPos($app.Hwnd, [IntPtr]::Zero, 20, 10, $size[0], $size[1], 0x0040 -bor 0x0004) | Out-Null
      $wr = Refresh-Root $app
      '=== ask ' + $size[0] + 'x' + $size[1] + ' actual ' + ($wr.R - $wr.L) + 'x' + ($wr.B - $wr.T) + ' at ' + $wr.L + ',' + $wr.T + ' iconic=' + [Hub]::IsIconic($app.Hwnd) + ' dpi=' + $app.Scale
      MicState $app
      foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Edit))) {
        if ([string]$e.Current.Name -ceq 'Chat message') {
          $r = $e.Current.BoundingRectangle
          $top = [int]($r.Y * $app.Scale); $bot = [int](($r.Y + $r.Height) * $app.Scale)
          'EDT [Chat message] off=' + $e.Current.IsOffscreen + ' top=' + $top + ' bottom=' + $bot + ' winBottom=' + $wr.B + ' gap=' + ($wr.B - $bot)
        }
      }
      $newest = -1.0
      foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Text))) {
        $n = [string]$e.Current.Name
        $r = $e.Current.BoundingRectangle
        if ($n.Length -eq 0 -or $r.Width -le 0) { continue }
        $x = $r.X * $app.Scale; $y = $r.Y * $app.Scale
        if ($x -lt 620 -or $y -lt 0) { continue }
        if ($y -gt $newest) { $newest = $y; $nn = $n }
      }
      'newest bubble: ' + $nn + ' y=' + [int]$newest
      Shot $app ("layout_" + $k + '_' + ($wr.R - $wr.L) + 'x' + ($wr.B - $wr.T))
    }
    exit 0
  }

  'resize:*' {
    # Prove the composer stays pinned when the window gets short/narrow.
    $k = $Phase.Split(':')[1]
    $app = Open-App $k
    'nav: ' + (Invoke-Btn $app.Root 'SMS' 'suffix')
    Start-Sleep -Seconds 2
    'cat: ' + (Invoke-Btn $app.Root 'SMS msgs' 'exact')
    Start-Sleep -Seconds 2
    'row: ' + (Open-FirstRow $app '')
    Start-Sleep -Seconds 2
    foreach ($size in @(@(1250, 990), @(900, 700), @(760, 560))) {
      # SWP_NOSIZE(0x0001)/SWP_NOMOVE(0x0002) must NOT be set; keep SHOWWINDOW|NOZORDER.
      $ok = [Hub]::SetWindowPos($app.Hwnd, [IntPtr]::Zero, 20, 10, $size[0], $size[1], 0x0040 -bor 0x0004)
      Start-Sleep -Seconds 2
      $wr = New-Object Hub+RECT
      [Hub]::GetWindowRect($app.Hwnd, [ref]$wr) | Out-Null
      'size asked ' + $size[0] + 'x' + $size[1] + ' ok=' + $ok + ' -> actual ' + ($wr.R - $wr.L) + 'x' + ($wr.B - $wr.T) + ' at ' + $wr.L + ',' + $wr.T
      MicState $app
      'composer: '
      foreach ($e in (Get-ByType $app.Root ([System.Windows.Automation.ControlType]::Edit))) {
        if ([string]$e.Current.Name -ceq 'Chat message') {
          $r = $e.Current.BoundingRectangle
          $top = [int]($r.Y * $app.Scale); $bot = [int](($r.Y + $r.Height) * $app.Scale)
          'EDT [Chat message] off=' + $e.Current.IsOffscreen + ' top=' + $top + ' bottom=' + $bot + ' winBottom=' + $wr.B + ' gap=' + ($wr.B - $bot)
        }
      }
      Shot $app ("resize_" + $k + '_' + $size[0] + 'x' + $size[1])
    }
    exit 0
  }

  'logs' {
    '--- A (host) ---'
    Last-Log (Join-Path $Work 'UssdApp.exe') 'LOG ui:' $Tail
    '--- B ---'
    Last-Log (Join-Path $Bdir 'UssdApp.exe') 'LOG ui:' $Tail
    exit 0
  }
}

'unknown phase ' + $Phase
exit 2
