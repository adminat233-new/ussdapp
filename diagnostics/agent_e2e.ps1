# C1 live proof: the always-awake agent, with the window shut.
#
# Nothing here trusts the app's own word. A dumb PowerShell relay (not part of
# the app) sits between the two profiles, logs every byte line it forwards, and
# the only thing asserted afterwards is what landed on disk and in the window's
# own trace file.
#
# Sequence:
#   instF  UssdAgent.exe --agent            (no window anywhere on this profile)
#   instE  UssdAgent.exe --send=...         (headless sender)
#   agent  decrypts, stores to instF\wake_inbox, starts UssdApp.exe --home=instF
#   window replays the stored message through its normal inbound path
#
# Asserts:
#   1. the agent held the relay slot while no window existed;
#   2. the chat crossed the relay sealed (no canary in its log);
#   3. the agent stored it and woke the window, naming the reason;
#   4. the woken window is the one owning that profile (same identity key);
#   5. the window replayed it exactly once into the chat log;
#   6. the hand-off inbox drained (no message can be shown twice).
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Admin\Documents\Default Project\ussdApp'
$agentExe = Join-Path $root 'Csharp\UssdAgent.exe'
$appExe = Join-Path $root 'Csharp\UssdApp.exe'
$port = 45692
$wire = Join-Path $root 'diagnostics\agent_relay.log'
$eDir = Join-Path $env:TEMP 'opencode\instE'
$fDir = Join-Path $env:TEMP 'opencode\instF'
$eOut = Join-Path $eDir 'send_out.txt'
$fOut = Join-Path $fDir 'agent_out.txt'
$numE = '7003256411'
$numF = '7003256422'
$canary = 'WAKE-CANARY-' + (Get-Date -Format 'HHmmss')
# The verdict goes to a file, not only to the console: the woken window is a GUI
# process that outlives the assertions, and a piped console can hold the caller
# open long after this script has decided pass or fail.
$run_log = Join-Path $root 'diagnostics\agent_run.txt'
try { Start-Transcript -Path $run_log -Force | Out-Null } catch { }

function Read-Text([string]$p) {
  if (-not (Test-Path $p)) { return '' }
  try {
    $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object System.IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Close() }
  } catch { return '' }
}

# --- clean slate: no window, no agent, no leftovers on either profile ---------
# Only processes running out of the test profiles are touched: killing every
# UssdApp on the machine would take a user's real session down with it.
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { $_.Kill() } catch { } }
Start-Sleep -Seconds 2
foreach ($d in @($eDir, $fDir)) {
  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
  foreach ($f in @('identity.key', 'peers_identity.txt', 'ussd_config.json', 'hang_trace.txt', 'startup.log')) {
    Remove-Item -Path (Join-Path $d $f) -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -Path (Join-Path $d 'chats') -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path (Join-Path $d 'wake_inbox') -Recurse -Force -ErrorAction SilentlyContinue
  Copy-Item $agentExe -Destination $d -Force
  Copy-Item $appExe -Destination $d -Force
  Copy-Item (Join-Path $root 'Csharp\UssdApp.ico') -Destination $d -Force -ErrorAction SilentlyContinue
}
'pre-flight: any UssdApp window running? ' + @(Get-Process UssdApp -ErrorAction SilentlyContinue).Count

Set-Content -Path $wire -Value ('=== relay on 127.0.0.1:' + $port + ' ' + (Get-Date -Format 'o'))
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
# A previous interrupted run can leave client sockets in TIME_WAIT on this port.
# ReuseAddress lets the dumb relay bind again without weakening what the test
# observes: it still logs every line and still refuses a second live listener.
$listener.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
$listener.Start()
$clients = New-Object System.Collections.ArrayList

function Wire([string]$s) { Add-Content -Path $wire -Value ((Get-Date -Format 'HH:mm:ss.fff') + ' ' + $s) }
function Drop-Client($x, [string]$why) {
  # Losing one client must never cost the relay the others: an unguarded write to
  # a dead socket used to bubble into the read loop and evict whichever client
  # was being served, which silently un-registered the live window.
  Wire ('! drop ' + $(if ($x.Num) { '#' + $x.Num } else { 'unnamed' }) + ' - ' + $why)
  $x.Num = ''
  try { $x.Tcp.Close() } catch { }
  [void]$clients.Remove($x)
}
function Send-Line($c, [string]$line) {
  try {
    $b = [System.Text.Encoding]::UTF8.GetBytes($line + "`n")
    $c.Stream.Write($b, 0, $b.Length)
    return $true
  } catch { Drop-Client $c ('write failed: ' + $_.Exception.Message); return $false }
}
function Find-ByNum([string]$num) {
  foreach ($x in $clients) { if ($x.Num -eq $num) { return $x } }
  return $null
}
function Broadcast-Peers {
  $recs = @()
  # Send-Line can drop a dead client, so enumerate a snapshot: modifying the
  # live ArrayList mid-loop used to throw "Collection was modified" and take
  # the surviving socket down with it.
  foreach ($x in @($clients)) { if ($x.Num) { $recs += ($x.Num + ',127.0.0.1,relaytest') } }
  foreach ($x in @($clients)) { if ($x.Num) { Send-Line $x ('PEERS|' + ($recs -join ';')) } }
}
function Handle-Line($c, [string]$line) {
  if (-not $line) { return }
  $line = $line.TrimStart([char]0xFEFF)      # the app's StreamWriter emits a BOM
  if (-not $line) { return }
  Wire ('<- ' + $line)
  $p = $line -split '\|', 4
  if ($p[0] -eq 'REG') {
    $num = $p[1].Trim()
    $tok = $p[2]
    # Mirror the app's own server rule, because the agent's stand-down depends on
    # it: same token = the same endpoint returning, so the old socket is closed
    # and replaced; a different token is a claim conflict and gets refused.
    foreach ($o in @($clients)) {
      if ($o.Num -eq $num -and $o -ne $c) {
        if ($o.Token -eq $tok) {
          Wire ('~ replacing #' + $num + ' (same token), closing the older socket')
          $o.Num = ''
          try { $o.Tcp.Close() } catch { }
        } else {
          Wire ('! #' + $num + ' already claimed by a different token, refused')
          Send-Line $c ('ERR|inuse|' + $num)
          return
        }
      }
    }
    $c.Token = $tok
    $c.Num = $num
    Send-Line $c ('OK|' + $num)
    Broadcast-Peers
  }
  elseif ($p[0] -eq 'MSG' -or $p[0] -eq 'RM') {
    $t = Find-ByNum $p[1].Trim()
    if ($t) { Send-Line $t $line; Wire ('-> ' + $p[1] + ' forwarded') }
    else { Wire ('-> ' + $p[1] + ' OFFLINE, not forwarded') }
  }
}
# One thread has to carry the relay and watch the files, so servicing is a
# function both the wake phase and the hand-back phase can call.
function Poll-Relay {
  if ($listener.Pending()) {
    $tc = $listener.AcceptTcpClient()
    [void]$clients.Add([pscustomobject]@{ Tcp = $tc; Stream = $tc.GetStream(); Num = ''; Token = ''; Pending = '' })
    Wire ('+ connection ' + $tc.Client.RemoteEndPoint)
  }
  foreach ($c in @($clients)) {
    try {
      while ($c.Stream.DataAvailable) {
        $buf = New-Object byte[] 16384
        $n = $c.Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { Drop-Client $c 'socket closed by peer'; break }
        $c.Pending += [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
        while ($c.Pending.Contains("`n")) {
          $i = $c.Pending.IndexOf("`n")
          $ln = $c.Pending.Substring(0, $i).TrimEnd("`r")
          $c.Pending = $c.Pending.Substring($i + 1)
          Handle-Line $c $ln
        }
      }
    } catch { Drop-Client $c ('read failed: ' + $_.Exception.Message) }
  }
}

# --- the receiver runs with NO window: only the agent ------------------------
$env:USSD_FAKE_MIC = '1'
$env:USSD_TRACE = '1'
$psAgent = Start-Process -FilePath (Join-Path $fDir 'UssdAgent.exe') `
  -ArgumentList @('--agent', "--home=$fDir", "--number=$numF", "--relay=127.0.0.1:$port", `
                 "--gui=$(Join-Path $fDir 'UssdApp.exe')", '--agent-timeout=150') `
  -WorkingDirectory $fDir -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $fOut -RedirectStandardError (Join-Path $fDir 'agent_err.txt')

$ready = (Get-Date).AddSeconds(25)
$connected = $false
while ((Get-Date) -lt $ready) {
  Poll-Relay
  if ((Read-Text $fOut) -match 'connected=True') { $connected = $true; break }
  Start-Sleep -Milliseconds 100
}
'agent connected=' + $connected + '  (window processes while it ran: ' + @(Get-Process UssdApp -ErrorAction SilentlyContinue).Count + ')'
$winAtSend = @(Get-Process UssdApp -ErrorAction SilentlyContinue).Count

# --- send to a profile that has no UI open -----------------------------------
$sendAt = Get-Date
if ($connected) {
  $psSend = Start-Process -FilePath (Join-Path $eDir 'UssdAgent.exe') `
    -ArgumentList @("--home=$eDir", "--number=$numE", "--relay=127.0.0.1:$port", `
                   "--send=$numF|$canary", '--linger=20') `
    -WorkingDirectory $eDir -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $eOut -RedirectStandardError (Join-Path $eDir 'send_err.txt')
}

# --- keep serving the relay while the window comes up (it costs tens of seconds)
$deadline = (Get-Date).AddSeconds(210)
$fTrace = Join-Path $fDir 'hang_trace.txt'
$wokeAt = $null
while ((Get-Date) -lt $deadline) {
  Poll-Relay
  if (-not $wokeAt -and (Read-Text $fTrace).IndexOf('wake replay') -ge 0) {
    $wokeAt = Get-Date
    Wire ('*** woken window replayed the stored chat at ' + (Get-Date -Format 'HH:mm:ss'))
  }
  if ($wokeAt -and ((Get-Date) - $wokeAt).TotalSeconds -gt 12) { break }
  Start-Sleep -Milliseconds 150
}
# --- phase 2: the window is open, and a listener starts anyway --------------
# The window re-registered with the same number token the agent had held, so a
# second listener must give the slot straight back instead of re-registering
# every 5 s and knocking the window offline in turn.
$regBefore = ([regex]::Matches((Read-Text $wire), [regex]::Escape('REG|' + $numF))).Count
$fOut2 = Join-Path $fDir 'agent_out2.txt'
$psAgent2 = Start-Process -FilePath (Join-Path $fDir 'UssdAgent.exe') `
  -ArgumentList @('--agent', "--home=$fDir", "--number=$numF", "--relay=127.0.0.1:$port", `
                 "--gui=$fDir\UssdApp.exe", '--agent-timeout=40') `
  -WorkingDirectory $fDir -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $fOut2 -RedirectStandardError (Join-Path $fDir 'agent_err2.txt')
$exited2 = $false
$d2 = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $d2) {
  Poll-Relay
  # HasExited on a Start-Process object can stay false after the process is gone.
  # WaitForExit(0) refreshes it without blocking the relay pump the window needs.
  if ($psAgent2.WaitForExit(0)) { $exited2 = $true; break }
  Start-Sleep -Milliseconds 150
}
# Then let the survivor settle. A fight over one number would keep producing
# REG lines from here on, so counting them is the actual measurement.
$settle = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $settle) { Poll-Relay; Start-Sleep -Milliseconds 150 }
$regDelta = ([regex]::Matches((Read-Text $wire), [regex]::Escape('REG|' + $numF))).Count - $regBefore
$agent2All = Read-Text $fOut2
# This PowerShell host returns $null for Process.ExitCode even after WaitForExit,
# so the agent's own "AGENT exit=0" line is the readable witness. Both the line
# and the process actually being gone are required; neither alone is enough.
$exit2 = if ($exited2 -and $agent2All -match 'AGENT exit=0') { 0 } else { $null }
'=== phase 2: second listener exit=' + $exit2 + '  REG lines for #' + $numF + ' since phase 2: ' + $regDelta
Get-Content $fOut2 -ErrorAction SilentlyContinue | Select-Object -Last 6

# --- phase 3: the open window must take traffic live, not from the inbox ----
$live = 'LIVE-CANARY-' + (Get-Date -Format 'HHmmss')
$eOut2 = Join-Path $eDir 'send_out2.txt'
$psSend2 = Start-Process -FilePath (Join-Path $eDir 'UssdAgent.exe') `
  -ArgumentList @("--home=$eDir", "--number=$numE", "--relay=127.0.0.1:$port", `
                 "--send=$numF|$live", '--linger=15') `
  -WorkingDirectory $eDir -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $eOut2 -RedirectStandardError (Join-Path $eDir 'send_err2.txt')
$liveAt = $null
$liveWitness = ''
$liveChat = Join-Path $fDir ('chats\chat_' + $numE + '.txt')
$d3 = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $d3) {
  Poll-Relay
  # A warm window sometimes writes the inbound line straight into the chat
  # store and only later (or never) into the trace. Both files are this
  # profile's own on-disk record; neither is the sender saying it succeeded.
  if ((Read-Text $fTrace).IndexOf($live) -ge 0) { $liveAt = Get-Date; $liveWitness = 'trace'; break }
  if ((Test-Path $liveChat) -and (Read-Text $liveChat).IndexOf($live) -ge 0) {
    $liveAt = Get-Date; $liveWitness = 'chat store'; break
  }
  Start-Sleep -Milliseconds 150
}
'live arrival: ' + $(if ($liveAt) { $liveAt.ToString('HH:mm:ss') + ' (' + $liveWitness + ')' } else { 'never' })

foreach ($c in @($clients)) { try { $c.Stream.Dispose() } catch { }; try { $c.Tcp.Close() } catch { } }
try { $listener.Stop() } catch { }
Start-Sleep -Seconds 2

'=== agent (instF) ==='
Get-Content $fOut -ErrorAction SilentlyContinue
'=== sender (instE) ==='
Get-Content $eOut -ErrorAction SilentlyContinue
'=== instF processes now ==='
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName + ' pid=' + $_.Id + ' ' + $_.Path }
'=== wake_inbox left on instF ==='
$ib = Join-Path $fDir 'wake_inbox'
if (Test-Path $ib) { @(Get-ChildItem $ib -Filter *.msg -ErrorAction SilentlyContinue).Count } else { 'no inbox dir' }
'=== instF chat store ==='
Get-ChildItem (Join-Path $fDir 'chats') -Filter *.txt -ErrorAction SilentlyContinue | ForEach-Object { $_.Name; Get-Content $_.FullName }

$agentAll = Read-Text $fOut
$sendAll = Read-Text $eOut
$traceAll = Read-Text $fTrace
$wireAll = Read-Text $wire
$chatFile = Join-Path $fDir ('chats\chat_' + $numF + '.txt')
$chatE = Join-Path $fDir ('chats\chat_' + $numE + '.txt')
$chatAll = ''
foreach ($cf in @($chatFile, $chatE)) { if (Test-Path $cf) { $chatAll += (Read-Text $cf) } }
$fpAgent = if ($agentAll -match 'identity=([0-9A-Fa-f-]+)') { $Matches[1] } else { '?' }
$fpWin = if ($traceAll -match 'identity key ([0-9A-Fa-f-]+)') { $Matches[1] } else { '?' }
$inboxCount = 0
if (Test-Path $ib) { $inboxCount = @(Get-ChildItem $ib -Filter *.msg -ErrorAction SilentlyContinue).Count }
$canaryHits = ([regex]::Matches($chatAll, [regex]::Escape($canary))).Count
$liveHits = ([regex]::Matches($chatAll, [regex]::Escape($live))).Count

$checks = @()
$checks += @{ n = 'agent took the relay slot with no window open'; ok = ($connected -and $winAtSend -eq 0); d = 'connected=' + $connected + ' windows_at_send=' + $winAtSend }
$checks += @{ n = 'relay never saw the message in clear'; ok = ($wireAll.IndexOf($canary) -lt 0 -and $wireAll -match 'ECHAT\|'); d = '' }
$checks += @{ n = 'agent stored the sealed chat for the window'; ok = ($agentAll -match 'AGENT stored a chat from #' + $numE); d = '' }
$checks += @{ n = 'agent woke the window and named the reason'; ok = ($agentAll -match 'AGENT woke the window \(chat from #' + $numE + '\)'); d = '' }
$checks += @{ n = 'a window for that profile came up'; ok = ((Read-Text $fTrace).Length -gt 0); d = 'trace lines=' + @($traceAll -split "`n").Count }
$checks += @{ n = 'window reused the same install identity key'; ok = ($fpWin -ne '?' -and $fpWin -eq $fpAgent); d = 'agent=' + $fpAgent + ' window=' + $fpWin }
$checks += @{ n = 'window replayed it through the inbound path'; ok = ($traceAll -match 'wake replay from #' + $numE -and $traceAll.IndexOf($canary) -ge 0); d = '' }
$checks += @{ n = 'message landed exactly once in the chat log'; ok = ($canaryHits -eq 1); d = 'occurrences=' + $canaryHits }
$checks += @{ n = 'sender saw the sealed chat accepted'; ok = ($sendAll -match 'RESULT sent=True' -and $sendAll -match 'sealedSession=locked'); d = '' }
$checks += @{ n = 'hand-off inbox drained (cannot show twice)'; ok = ($inboxCount -eq 0); d = 'left=' + $inboxCount }
$checks += @{ n = 'a late listener hands the slot back, not a fight'; ok = ($null -ne $exit2 -and $exit2 -eq 0 -and $agent2All -match 'standing down'); d = 'exit=' + $exit2 }
$checks += @{ n = 'no registration ping-pong over one number'; ok = ($regDelta -le 2); d = 'REG lines during phase 2 + settle = ' + $regDelta }
$checks += @{ n = 'the open window takes traffic live'; ok = ($null -ne $liveAt); d = $liveWitness }
$checks += @{ n = 'live traffic did not detour through the inbox'; ok = ($inboxCount -eq 0); d = 'inbox=' + $inboxCount }
$checks += @{ n = 'both messages landed once each'; ok = ($canaryHits -eq 1 -and $liveHits -eq 1); d = 'wake=' + $canaryHits + ' live=' + $liveHits }

'=== verdict ==='
$allOk = $true
foreach ($c in $checks) {
  $s = if ($c.ok) { 'PASS' } else { $allOk = $false; 'FAIL' }
  '{0,-6} {1} {2}' -f $s, $c.n, $c.d
}
'OVERALL: ' + $(if ($allOk) { 'PASS' } else { 'FAIL' })
'canary was: ' + $canary
'wake latency: ' + $(if ($wokeAt) { [int]($wokeAt - $sendAt).TotalSeconds } else { 'n/a' }) + ' s from send to replay (the window cold start dominates)'

# Close what this test opened, or the next build fails on a locked exe.
'=== closing the woken window ==='
# These are hidden test processes with no usable main window. CloseMainWindow()
# can wait forever on a WPF window whose relay thread is already gone, so end
# them directly; no user session is touched because every path is under our temp
# profiles.
Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path -and $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false }
} | ForEach-Object { try { Stop-Process -Id $_.Id -Force } catch { } }
Start-Sleep -Seconds 2
'remaining test processes: ' + @(Get-Process UssdApp, UssdAgent -ErrorAction SilentlyContinue | Where-Object {
  try { $_.Path.StartsWith((Join-Path $env:TEMP 'opencode'), 'OrdinalIgnoreCase') } catch { $false } }).Count
try { Stop-Transcript | Out-Null } catch { }
if (-not $allOk) { exit 1 }
exit 0
