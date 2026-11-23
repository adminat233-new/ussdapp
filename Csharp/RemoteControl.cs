using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =========================================================================
    // RemoteControl — consent-gated device control for the autonomous agent.
    //
    // Design rules (non-negotiable):
    //   1. Every command is queued as a *pending request* first.
    //   2. Nothing executes until the local user approves it via
    //      PermissionRequest event (shown as a dialog in the UI).
    //   3. The approving user can restrict scope: "this session only",
    //      "this command only", or "always allow this command".
    //   4. All executed commands are written to an append-only audit log.
    //   5. The remote party receives only the output — never the approval
    //      dialog result or the user's identity.
    //   6. A kill switch (EmergencyRevoke) immediately clears all permissions
    //      and rejects any queued requests.
    //
    // Commands map to safe, bounded operations:
    //   screenshot   — capture the screen
    //   sysinfo      — CPU / RAM / uptime / hostname
    //   listfiles    — list a directory the user picks
    //   readfile     — read a file (path must be in allowed list)
    //   runussd      — run a USSD code (routed through VoipService)
    //   sendsms      — send SMS to a number via the modem
    //   shell        — DISABLED — never permitted, not even with approval
    // =========================================================================
    public sealed class RemoteControl
    {
        public const int MAX_QUEUE = 20;

        // ── Events ───────────────────────────────────────────────────────
        // Raised on the calling thread; the UI must marshal to Dispatcher.
        public event Action<PermissionRequest> PermissionRequested;
        public event Action<string, string> CommandExecuted;    // commandId, output
        public event Action<PermissionRequest, string> RequestCompleted; // request, output
        public event Action<string> AuditEntry;                 // one log line

        // ── State ────────────────────────────────────────────────────────
        private readonly object _lock = new object();
        private readonly Queue<PermissionRequest> _pending = new Queue<PermissionRequest>();
        private readonly HashSet<string> _alwaysAllow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<DateTime>> _requestTimestamps = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _denialCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _blockedPeers = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private volatile bool _revoked = false;
        private readonly string _auditPath;

        public RemoteControl(string profileDir)
        {
            _auditPath = Path.Combine(profileDir, "remote_audit.log");
        }

        // ── Rate Limiting & Brute Force Defense ───────────────────────────
        private bool IsPeerRateLimitedOrBlocked(string from, out string reason)
        {
            reason = null;
            if (string.IsNullOrEmpty(from)) from = "unknown";
            DateTime now = DateTime.UtcNow;

            lock (_lock)
            {
                // Check if peer is currently blocked
                DateTime blockUntil;
                if (_blockedPeers.TryGetValue(from, out blockUntil))
                {
                    if (now < blockUntil)
                    {
                        reason = "PEER_TEMPORARILY_BLOCKED (" + (int)(blockUntil - now).TotalMinutes + "m remaining)";
                        return true;
                    }
                    else
                    {
                        _blockedPeers.Remove(from);
                        _denialCounts[from] = 0;
                    }
                }

                // Check rate limiting: max 5 requests per 60 seconds
                List<DateTime> history;
                if (!_requestTimestamps.TryGetValue(from, out history))
                {
                    history = new List<DateTime>();
                    _requestTimestamps[from] = history;
                }
                history.RemoveAll(t => (now - t).TotalSeconds > 60);

                if (history.Count >= 5)
                {
                    reason = "RATE_LIMIT_EXCEEDED (max 5 req/min)";
                    return true;
                }

                history.Add(now);
            }
            return false;
        }

        // ── Public API ───────────────────────────────────────────────────

        /// <summary>Queue a command from a remote peer. Returns the request ID.</summary>
        public string Request(string from, string command, string arg)
        {
            if (_revoked) return null;

            string rateReason;
            if (IsPeerRateLimitedOrBlocked(from, out rateReason))
            {
                Audit("BLOCKED (" + rateReason + "): from=" + from + " cmd=" + command);
                return null;
            }

            if (IsBannedCommand(command))
            {
                Audit("REJECTED (banned command): from=" + from + " cmd=" + command);
                return null;
            }
            if (_pending.Count >= MAX_QUEUE) return null;

            string id = DateTime.UtcNow.Ticks.ToString("X") + "_" + command;
            var req = new PermissionRequest
            {
                Id = id, From = from, Command = command, Arg = arg,
                RequestedAt = DateTime.Now
            };

            // If the user previously approved "always allow" for this command, run it immediately.
            if (_alwaysAllow.Contains(command))
            {
                Audit("AUTO-APPROVED (always-allow): " + Fmt(req));
                ExecuteNow(req);
                return id;
            }

            lock (_lock) _pending.Enqueue(req);
            Audit("QUEUED: " + Fmt(req));

            var h = PermissionRequested;
            if (h != null) h(req);
            return id;
        }

        /// <summary>Called by the UI when the user approves a request.</summary>
        public void Approve(string requestId, bool alwaysAllow)
        {
            if (_revoked) return;
            PermissionRequest req = Dequeue(requestId);
            if (req == null) return;
            if (alwaysAllow) lock (_lock) _alwaysAllow.Add(req.Command);

            // Successful approval resets denial counts for this peer
            lock (_lock)
            {
                if (!string.IsNullOrEmpty(req.From))
                    _denialCounts[req.From] = 0;
            }

            Audit("APPROVED" + (alwaysAllow ? " (always)" : "") + ": " + Fmt(req));
            ExecuteNow(req);
        }

        /// <summary>Called by the UI when the user denies a request.</summary>
        public void Deny(string requestId)
        {
            PermissionRequest req = Dequeue(requestId);
            if (req == null) return;

            // Track denials for brute-force defense (3 denials -> 10m block)
            if (!string.IsNullOrEmpty(req.From))
            {
                lock (_lock)
                {
                    int count = 0;
                    _denialCounts.TryGetValue(req.From, out count);
                    count++;
                    _denialCounts[req.From] = count;
                    if (count >= 3)
                    {
                        _blockedPeers[req.From] = DateTime.UtcNow.AddMinutes(10);
                        Audit("DEFENSE: Peer '" + req.From + "' blocked for 10 minutes due to 3 denials.");
                    }
                }
            }

            Audit("DENIED: " + Fmt(req));
            var h = CommandExecuted;
            if (h != null) h(req.Id, "DENIED");
            var hr = RequestCompleted;
            if (hr != null) hr(req, "DENIED");
        }

        /// <summary>Immediately clears all sessions, permissions, and queued requests.</summary>
        public void EmergencyRevoke()
        {
            _revoked = true;
            lock (_lock) { _alwaysAllow.Clear(); _pending.Clear(); }
            Audit("EMERGENCY REVOKE — all remote control permissions cleared.");
        }

        public void ResetRevoke()
        {
            _revoked = false;
            Audit("Remote control re-enabled by local user.");
        }

        public bool IsRevoked { get { return _revoked; } }
        public int PendingCount { get { lock (_lock) return _pending.Count; } }

        // ── Internal execution ───────────────────────────────────────────

        private static bool IsBannedCommand(string cmd)
        {
            // shell / exec is permanently disabled — no approval path exists for it.
            return string.Equals(cmd, "shell", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(cmd, "exec",  StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(cmd, "reboot",StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(cmd, "format",StringComparison.OrdinalIgnoreCase);
        }

        private void ExecuteNow(PermissionRequest req)
        {
            Thread t = new Thread((ThreadStart)delegate
            {
                string output;
                try { output = RunCommand(req.Command, req.Arg); }
                catch (Exception ex) { output = "ERROR: " + ex.Message; }
                Audit("EXECUTED: " + Fmt(req) + " -> " + output.Length + " chars");
                var h = CommandExecuted;
                if (h != null) h(req.Id, output);
                var hr = RequestCompleted;
                if (hr != null) hr(req, output);
            });
            t.IsBackground = true;
            t.Name = "RC_" + req.Command;
            t.Start();
        }

        private string RunCommand(string command, string arg)
        {
            switch (command.ToLowerInvariant())
            {
                case "screenshot":
                    return CaptureScreen();

                case "sysinfo":
                    return GetSysInfo();

                case "listfiles":
                    return ListFiles(arg);

                case "readfile":
                    return ReadFileSafe(arg);

                case "runussd":
                    // Caller wires RunUssdRequested to execute via VoipService
                    var hu = RunUssdRequested;
                    if (hu != null) hu(arg);
                    return "USSD queued: " + arg;

                case "sendsms":
                    // Format: "number|body"
                    int bar = (arg ?? "").IndexOf('|');
                    if (bar < 0) return "ERROR: arg must be number|body";
                    var hms = SendSmsRequested;
                    if (hms != null) hms(arg.Substring(0, bar), arg.Substring(bar + 1));
                    return "SMS queued to " + arg.Substring(0, bar);

                case "ping":
                    return "PONG " + DateTime.Now.ToString("HH:mm:ss");

                case "locatedevice":
                    return LocateDevice();

                case "ringdevice":
                    return RingDevice();

                case "lockscreen":
                    return LockScreen();

                case "derp_status":
                case "mesh":
                    return "DERP_STATUS: experimental frame router on port 9005; opaque payloads; not a TLS tunnel";

                default:
                    return "UNKNOWN_COMMAND: " + command;
            }
        }

        // These callbacks let the UI wire actual actions without RemoteControl
        // knowing about the modem or VoipService directly.
        public event Action<string> RunUssdRequested;    // ussd code
        public event Action<string, string> SendSmsRequested;  // number, body

        // ── Commands ─────────────────────────────────────────────────────

        private string CaptureScreen()
        {
            try
            {
                // Capture primary screen to a JPEG in the profile dir
                int w = (int)System.Windows.SystemParameters.PrimaryScreenWidth;
                int h = (int)System.Windows.SystemParameters.PrimaryScreenHeight;
                using (System.Drawing.Bitmap bmp = new System.Drawing.Bitmap(w, h))
                using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage(bmp))
                {
                    g.CopyFromScreen(0, 0, 0, 0, new System.Drawing.Size(w, h));
                    string path = Path.Combine(Path.GetDirectoryName(_auditPath), "rc_screenshot.jpg");
                    bmp.Save(path, System.Drawing.Imaging.ImageFormat.Jpeg);
                    long size = new FileInfo(path).Length;
                    return "SCREENSHOT:" + path + ":SIZE=" + size;
                }
            }
            catch (Exception ex) { return "SCREENSHOT_ERR: " + ex.Message; }
        }

        private string GetSysInfo()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("hostname=" + System.Net.Dns.GetHostName());
            sb.AppendLine("os=" + Environment.OSVersion.VersionString);
            sb.AppendLine("machine=" + Environment.MachineName);
            sb.AppendLine("uptime_min=" + (int)(Environment.TickCount / 60000));
            sb.AppendLine("cpu_count=" + Environment.ProcessorCount);
            sb.AppendLine("time_utc=" + DateTime.UtcNow.ToString("o"));
            long ram = 0;
            try
            {
                using (System.Management.ManagementObjectSearcher mos =
                    new System.Management.ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem"))
                {
                    foreach (System.Management.ManagementObject mo in mos.Get())
                        ram = Convert.ToInt64(mo["TotalVisibleMemorySize"]);
                }
            }
            catch { }
            if (ram > 0) sb.AppendLine("ram_kb=" + ram);
            return sb.ToString();
        }

        private string ListFiles(string dir)
        {
            if (string.IsNullOrEmpty(dir)) dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            dir = Path.GetFullPath(dir);
            if (!Directory.Exists(dir)) return "NOT_FOUND: " + dir;
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DIR: " + dir);
            foreach (string f in Directory.GetFileSystemEntries(dir))
            {
                try
                {
                    FileAttributes a = File.GetAttributes(f);
                    bool isDir = (a & FileAttributes.Directory) != 0;
                    string size = isDir ? "<DIR>" : new FileInfo(f).Length.ToString();
                    sb.AppendLine((isDir ? "d " : "f ") + size.PadLeft(12) + "  " + Path.GetFileName(f));
                }
                catch { }
            }
            return sb.ToString();
        }

        private string ReadFileSafe(string path)
        {
            if (string.IsNullOrEmpty(path)) return "ERROR: no path";
            path = Path.GetFullPath(path);
            // Only allow reading within the user's documents or profile dir
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string prof = Path.GetDirectoryName(_auditPath);
            bool safe = path.StartsWith(docs, StringComparison.OrdinalIgnoreCase) ||
                        path.StartsWith(prof,  StringComparison.OrdinalIgnoreCase);
            if (!safe) return "ACCESS_DENIED: path not in allowed scope";
            if (!File.Exists(path)) return "NOT_FOUND: " + path;
            long size = new FileInfo(path).Length;
            if (size > 512 * 1024) return "TOO_LARGE: " + size + " bytes (limit 512 KB)";
            return File.ReadAllText(path, Encoding.UTF8);
        }

        private string LocateDevice()
        {
            try
            {
                double lat, lon;
                string source;
                if (TrackerBridge.TryGetSystemLocation(out lat, out lon, out source))
                {
                    return string.Format(CultureInfo.InvariantCulture, "LOCATION:lat={0:F6},lon={1:F6},source={2},time={3}",
                        lat, lon, source, DateTime.UtcNow.ToString("o"));
                }
                return "LOCATION_UNAVAILABLE: System Location API or network geolocation failed.";
            }
            catch (Exception ex)
            {
                return "LOCATION_ERR: " + ex.Message;
            }
        }

        private string RingDevice()
        {
            try
            {
                for (int i = 0; i < 5; i++)
                {
                    System.Media.SystemSounds.Exclamation.Play();
                    Thread.Sleep(600);
                }
                return "RING_PLAYED: 5 alert chimes completed.";
            }
            catch (Exception ex)
            {
                return "RING_ERR: " + ex.Message;
            }
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool LockWorkStation();

        private string LockScreen()
        {
            try
            {
                bool ok = LockWorkStation();
                return ok ? "SCREEN_LOCKED: Workstation locked successfully." : "LOCK_FAILED: user32 LockWorkStation returned false.";
            }
            catch (Exception ex)
            {
                return "LOCK_ERR: " + ex.Message;
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────

        private PermissionRequest Dequeue(string id)
        {
            lock (_lock)
            {
                Queue<PermissionRequest> tmp = new Queue<PermissionRequest>();
                PermissionRequest found = null;
                while (_pending.Count > 0)
                {
                    PermissionRequest r = _pending.Dequeue();
                    if (r.Id == id) found = r;
                    else tmp.Enqueue(r);
                }
                while (tmp.Count > 0) _pending.Enqueue(tmp.Dequeue());
                return found;
            }
        }

        private void Audit(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg;
            try { File.AppendAllText(_auditPath, line + "\n"); } catch { }
            var h = AuditEntry;
            if (h != null) h(line);
        }

        private static string Fmt(PermissionRequest r)
        {
            return string.Format("id={0} from={1} cmd={2} arg={3}", r.Id, r.From, r.Command,
                r.Arg != null && r.Arg.Length > 60 ? r.Arg.Substring(0, 60) + "…" : r.Arg);
        }
    }

    // ── Permission request ────────────────────────────────────────────────
    public sealed class PermissionRequest
    {
        public string Id;
        public string From;
        public string Command;
        public string Arg;
        public DateTime RequestedAt;
    }
}
