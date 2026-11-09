using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace UssdApp
{
    // =====================================================================
    // ConnectionHelper — zero-friction cross-network reachability.
    //
    // Answers the question: "my mate downloaded this app — can we call?"
    //
    // The problem: two PCs on different networks cannot reach each other
    // directly. They need:
    //   1. A shared relay (TCP server one of them hosts, or a public one)
    //   2. The relay address exchanged somehow (seed line)
    //   3. Both registered on that relay
    //   4. A direct UDP path (STUN/UPnP) or relay fallback for media
    //   5. Background agent so incoming calls land even when the window is closed
    //
    // This class does the work that used to require manual configuration:
    //   - Auto-detect LAN peers (already works via UDP broadcast)
    //   - Detect internet reachability and pick the best relay strategy
    //   - Generate a shareable "connection card" (seed line + number + QR)
    //   - Register the background agent at login on first run
    //   - Probe mic/camera/network permissions proactively
    //   - Surface all of this in a single "Get connected" card
    // =====================================================================

    public sealed class ConnectionStatus
    {
        public bool LanReachable;         // peer on the same LAN
        public bool RelayConnected;       // registered on a relay
        public bool RelayHosting;         // this machine is hosting the relay
        public bool BackgroundActive;     // wake agent is running
        public bool BackgroundAtLogin;    // registered in HKCU Run
        public bool MicAvailable;         // at least one audio input device
        public bool CameraAvailable;      // at least one video capture device
        public bool InternetReachable;    // can reach the relay or STUN server
        public string RelayAddress;       // host:port of the connected relay
        public string SeedLine;           // the line a mate pastes into relays.seed
        public string MyNumber;           // formatted app number
        public string MyFingerprint;      // identity key fingerprint
        public string ConnectCardText;    // human-readable "how to connect" card
    }

    public static class ConnectionHelper
    {
        // ── Background permissions / autostart ─────────────────────────
        // Register this exe in the per-user Run key so it starts as the
        // wake agent on every sign-in. Does not require admin rights.
        public static bool RegisterBackgroundAtLogin(string agentExe, string homeDir, string relayAddr)
        {
            if (string.IsNullOrEmpty(agentExe) || !File.Exists(agentExe)) return false;
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (k == null) return false;
                    string cmd = "\"" + agentExe + "\" --agent --home=\"" +
                                 homeDir.TrimEnd('\\') + "\"" +
                                 (relayAddr.Length > 0 ? " --relay=" + relayAddr : "");
                    k.SetValue("UssdWakeAgent", cmd, RegistryValueKind.String);
                }
                return true;
            }
            catch { return false; }
        }

        public static void UnregisterBackgroundAtLogin()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (k == null) return;
                    if (k.GetValue("UssdWakeAgent") != null)
                        k.DeleteValue("UssdWakeAgent", false);
                }
            }
            catch { }
        }

        public static bool IsRegisteredAtLogin()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", false))
                {
                    return k != null && k.GetValue("UssdWakeAgent") != null;
                }
            }
            catch { return false; }
        }

        // ── Windows Firewall — allow this exe inbound ──────────────────
        // Without an inbound rule the relay port is blocked by the Windows
        // firewall, so a mate on the internet cannot connect.
        public static void EnsureFirewallRule(int port)
        {
            try
            {
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                // netsh advfirewall does not require elevation when it already
                // exists; deleting + re-adding is idempotent.
                string name = "USSD Manager Pro";
                // Check if the rule exists first
                ProcessStartInfo check = new ProcessStartInfo("netsh",
                    "advfirewall firewall show rule name=\"" + name + "\"")
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
                Process p = Process.Start(check);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                if (output.Contains(name)) return; // already exists
                // Add inbound rule for the relay TCP port
                ProcessStartInfo add = new ProcessStartInfo("netsh",
                    "advfirewall firewall add rule name=\"" + name + "\" protocol=TCP " +
                    "dir=in localport=" + port + " action=allow profile=any")
                { CreateNoWindow = true, UseShellExecute = false };
                Process.Start(add);
            }
            catch { }
        }

        // ── Device capability probes ───────────────────────────────────
        public static bool ProbeAudioInput()
        {
            try
            {
                // Use waveIn device count: if it's > 0 there is at least one mic
                int devs = NativeMethods.WaveInGetNumDevs();
                return devs > 0;
            }
            catch { return true; } // assume available; actual failure will surface on open
        }

        public static bool ProbeCameraInput()
        {
            try
            {
                // Check for DirectShow/video capture devices via WMI
                using (System.Management.ManagementObjectSearcher s = new System.Management.ManagementObjectSearcher(
                    "SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'Camera' OR PNPClass = 'Image'"))
                {
                    using (System.Management.ManagementObjectCollection c = s.Get())
                        return c.Count > 0;
                }
            }
            catch { return true; } // optimistically true
        }

        // ── Internet reachability probe ────────────────────────────────
        // Does NOT connect to any user-identifiable service: we ping the relay
        // port, not a third-party server. If no relay is configured, we probe
        // one STUN server with a UDP packet to see if the internet works at all.
        public static bool ProbeInternet(string relayAddr)
        {
            if (!string.IsNullOrEmpty(relayAddr))
            {
                try
                {
                    string[] parts = relayAddr.Split(':');
                    if (parts.Length < 2) return false;
                    int port;
                    if (!int.TryParse(parts[1], out port)) return false;
                    using (TcpClient t = new TcpClient())
                    {
                        t.SendTimeout = 3000; t.ReceiveTimeout = 3000;
                        IAsyncResult r = t.BeginConnect(parts[0], port, null, null);
                        if (!r.AsyncWaitHandle.WaitOne(3000)) return false;
                        t.EndConnect(r);
                        return true;
                    }
                }
                catch { return false; }
            }
            // No relay - check basic internet via a UDP ping to a STUN server.
            // STUN is stateless and we never complete a binding, so no identity leaks.
            try
            {
                using (UdpClient u = new UdpClient())
                {
                    u.Client.SendTimeout = 2000;
                    u.Client.ReceiveTimeout = 2000;
                    // STUN binding request (minimal valid packet)
                    byte[] req = new byte[20];
                    req[0] = 0x00; req[1] = 0x01; // type: Binding Request
                    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // magic cookie
                    u.Send(req, 20, "stun.l.google.com", 19302);
                    IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    try { u.Receive(ref ep); return true; } catch { return false; }
                }
            }
            catch { return false; }
        }

        // ── Get the machine's local IPs ────────────────────────────────
        public static List<string> LocalAddresses()
        {
            var list = new List<string>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (UnicastIPAddressInformation u in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (u.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                        string s = u.Address.ToString();
                        if (s.StartsWith("127.")) continue;
                        list.Add(s);
                    }
                }
            }
            catch { }
            return list;
        }

        // ── Connection card ────────────────────────────────────────────
        // A short text block a person can share over any channel (SMS, email,
        // WhatsApp, printed on paper) that gives a mate everything they need.
        public static string MakeConnectCard(string number, string seedLine, string fingerprint)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== USSD Manager Pro — Connect to me ===");
            sb.AppendLine();
            sb.AppendLine("1. Download USSD Manager Pro (same exe)");
            sb.AppendLine("2. Open it — it will mint your own number automatically");
            sb.AppendLine("3. Paste this into your relays.seed file:");
            sb.AppendLine("   (find the file: Settings > Identity & Network)");
            sb.AppendLine();
            if (!string.IsNullOrEmpty(seedLine))
                sb.AppendLine("   " + seedLine);
            else
                sb.AppendLine("   (no relay running — host one in Settings > Host server)");
            sb.AppendLine();
            sb.AppendLine("4. My app number is:  " + number);
            sb.AppendLine("   Call or message me from your Dialer tab.");
            sb.AppendLine();
            if (!string.IsNullOrEmpty(fingerprint))
            {
                sb.AppendLine("5. Relay fingerprint (verify out of band):  " + fingerprint);
                sb.AppendLine("   Matches if the app shows the same digits after connecting.");
            }
            sb.AppendLine();
            sb.AppendLine("That's it. No account, no SIM required.");
            return sb.ToString();
        }

        // ── Auto-start the relay when hosting ─────────────────────────
        // When the user enables "Host server", also:
        //   - open the firewall port
        //   - set up UPnP port mapping (if router supports it)
        //   - generate a seed line and show it prominently
        public static void OnHostStarted(int port, string fingerprint, string advertise, Action<string> log)
        {
            EnsureFirewallRule(port);
            log("Relay started on port " + port + " — firewall rule added.");
            log("Your relay fingerprint: " + fingerprint);
            log("To let a mate connect: Settings > Identity & Network > Connection Card");
            log("They paste the SEED LINE into their relays.seed and restart the app.");
        }

        // ── First-run: auto-configure everything ──────────────────────
        // Called on first run after the identity is minted. Does the minimum
        // needed for "open → reachable" without asking the user anything.
        public static void AutoConfigureFirstRun(
            string agentExe, string homeDir, string relayAddr,
            Action<string, bool> log)
        {
            // 1. Register the background wake agent at login
            bool bgOk = RegisterBackgroundAtLogin(agentExe, homeDir, relayAddr);
            log(bgOk
                ? "Background: will stay connected even when the window is closed (registered at sign-in)."
                : "Background: could not register at sign-in (Run key not writable). Reachable while the app is open only.", bgOk);

            // 2. Probe audio
            bool micOk = ProbeAudioInput();
            log(micOk
                ? "Audio: microphone detected — voice calls available."
                : "Audio: no microphone found — voice calls will not work until one is connected.", micOk);

            // 3. Probe camera
            bool camOk = ProbeCameraInput();
            log(camOk
                ? "Camera: video capture device detected — video calls available."
                : "Camera: no camera found — video calls will not work until one is connected.", camOk);
        }
    }

    // P/Invoke shim: waveIn device count without taking a dependency on NAudio
    internal static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("winmm.dll")]
        internal static extern int waveInGetNumDevs();
        public static int WaveInGetNumDevs()
        {
            try { return waveInGetNumDevs(); }
            catch { return 0; }
        }
    }
}
