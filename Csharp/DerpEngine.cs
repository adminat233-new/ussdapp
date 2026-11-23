using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =========================================================================
    // Deterministic Encrypted Relay Protocol (DERP) frame router.
    //
    // This is an experimental TCP fallback transport, not a TLS server and not
    // yet wired into live call media. It carries opaque frames: the router only
    // reads the destination key and forwards the ciphertext, so it never sees
    // call key material or decoded media.
    //
    // Wire shape:
    //   greeting: "DERP1" (5 bytes)
    //   frame:    network-order 4-byte body length, then body
    //   body[0]:  frame type, body[1..]: payload
    //
    // Frame types:
    //   0x01 CLIENT_INFO  UTF-8 node key, registers the connection
    //   0x02 SERVER_INFO  UTF-8 status line
    //   0x03 SEND_PACKET  1-byte dest length, dest key, opaque ciphertext
    //   0x04 RECV_PACKET  1-byte source length, source key, opaque ciphertext
    //   0x05 KEEPALIVE
    //   0x06 PING
    // =========================================================================

    public sealed class DerpFrame
    {
        public const byte TYPE_CLIENT_INFO = 0x01;
        public const byte TYPE_SERVER_INFO = 0x02;
        public const byte TYPE_SEND_PACKET = 0x03;
        public const byte TYPE_RECV_PACKET = 0x04;
        public const byte TYPE_KEEPALIVE   = 0x05;
        public const byte TYPE_PING        = 0x06;

        public byte Type;
        public byte[] Payload;
    }

    public sealed class DerpMeshRouter
    {
        private const int MaxFrameBytes = 65536;
        private const int MaxClients = 64;

        private sealed class Session
        {
            public TcpClient Client;
            public NetworkStream Stream;
            public readonly object WriteLock = new object();
            public string NodeKey;
        }

        private readonly string _localNodeKey;
        private readonly int _relayPort;
        private readonly Dictionary<string, Session> _clients = new Dictionary<string, Session>();
        private readonly object _clientsLock = new object();
        private TcpListener _listener;
        private volatile bool _running;
        private int _framesRouted;

        public DerpMeshRouter(string localNodeKey, int relayPort)
        {
            _localNodeKey = localNodeKey ?? "node_local";
            _relayPort = relayPort > 0 ? relayPort : 9005;
        }

        public int ClientCount
        {
            get { lock (_clientsLock) return _clients.Count; }
        }

        public int FramesRouted
        {
            get { return _framesRouted; }
        }

        public bool Running
        {
            get { return _running; }
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            try
            {
                _listener = new TcpListener(IPAddress.Any, _relayPort);
                _listener.Start();
                Thread t = new Thread(ListenLoop);
                t.IsBackground = true;
                t.Name = "DerpRouter_Listen";
                t.Start();
            }
            catch
            {
                _running = false;
                try { if (_listener != null) _listener.Stop(); } catch { }
                _listener = null;
            }
        }

        public void Stop()
        {
            _running = false;
            try { if (_listener != null) _listener.Stop(); } catch { }
            lock (_clientsLock)
            {
                foreach (Session s in _clients.Values)
                {
                    try { if (s.Client != null) s.Client.Close(); } catch { }
                }
                _clients.Clear();
            }
        }

        private void ListenLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    Thread handler = new Thread(delegate() { HandleClient(client); });
                    handler.IsBackground = true;
                    handler.Start();
                }
                catch
                {
                    if (!_running) break;
                }
            }
        }

        private void HandleClient(TcpClient client)
        {
            Session session = new Session();
            session.Client = client;
            try
            {
                session.Stream = client.GetStream();
                session.Stream.ReadTimeout = 15000;
                session.Stream.WriteTimeout = 15000;

                byte[] magic = new byte[5];
                if (!ReadExact(session.Stream, magic, 0, 5) ||
                    Encoding.ASCII.GetString(magic) != "DERP1") return;

                Send(session, BuildFrame(DerpFrame.TYPE_SERVER_INFO,
                    Encoding.UTF8.GetBytes("DERP_SERVER_OK|MTU=1420|NODE=" + _localNodeKey)));

                while (_running)
                {
                    DerpFrame frame = ReadFrame(session.Stream);
                    if (frame == null) break;
                    if (frame.Payload == null) continue;

                    if (frame.Type == DerpFrame.TYPE_CLIENT_INFO)
                    {
                        string key = CleanKey(Encoding.UTF8.GetString(frame.Payload));
                        if (key.Length == 0)
                        {
                            Send(session, Status("ERR|badkey"));
                            continue;
                        }
                        bool full = false;
                        lock (_clientsLock)
                        {
                            if (session.NodeKey != null && _clients.ContainsKey(session.NodeKey) &&
                                object.ReferenceEquals(_clients[session.NodeKey], session))
                                _clients.Remove(session.NodeKey);
                            if (session.NodeKey == null && !_clients.ContainsKey(key) && _clients.Count >= MaxClients)
                            {
                                full = true;
                            }
                            else
                            {
                                Session old;
                                if (_clients.TryGetValue(key, out old) && !object.ReferenceEquals(old, session))
                                {
                                    try { if (old.Client != null) old.Client.Close(); } catch { }
                                }
                                _clients[key] = session;
                                session.NodeKey = key;
                            }
                        }
                        if (full) { Send(session, Status("ERR|full")); continue; }
                        Send(session, Status("OK|registered|NODE=" + key));
                    }
                    else if (frame.Type == DerpFrame.TYPE_SEND_PACKET)
                    {
                        Route(session, frame.Payload);
                    }
                    else if (frame.Type == DerpFrame.TYPE_PING)
                    {
                        Send(session, BuildFrame(DerpFrame.TYPE_KEEPALIVE, new byte[0]));
                    }
                }
            }
            catch { }
            finally
            {
                if (session.NodeKey != null)
                {
                    lock (_clientsLock)
                    {
                        Session current;
                        if (_clients.TryGetValue(session.NodeKey, out current) &&
                            object.ReferenceEquals(current, session))
                            _clients.Remove(session.NodeKey);
                    }
                }
                try { client.Close(); } catch { }
            }
        }

        private void Route(Session from, byte[] payload)
        {
            if (from == null || from.NodeKey == null || payload == null || payload.Length < 2)
            {
                Send(from, Status("ERR|badpacket"));
                return;
            }
            int keyLen = payload[0];
            if (keyLen <= 0 || keyLen > 128 || payload.Length <= keyLen + 1)
            {
                Send(from, Status("ERR|badpacket"));
                return;
            }
            string destKey = CleanKey(Encoding.UTF8.GetString(payload, 1, keyLen));
            byte[] cipher = new byte[payload.Length - keyLen - 1];
            Buffer.BlockCopy(payload, keyLen + 1, cipher, 0, cipher.Length);
            if (destKey.Length == 0 || cipher.Length == 0)
            {
                Send(from, Status("ERR|badpacket"));
                return;
            }

            byte[] srcBytes = Encoding.UTF8.GetBytes(from.NodeKey);
            if (srcBytes.Length > 255)
            {
                Send(from, Status("ERR|badkey"));
                return;
            }
            byte[] delivery = new byte[1 + srcBytes.Length + cipher.Length];
            delivery[0] = (byte)srcBytes.Length;
            Buffer.BlockCopy(srcBytes, 0, delivery, 1, srcBytes.Length);
            Buffer.BlockCopy(cipher, 0, delivery, 1 + srcBytes.Length, cipher.Length);

            Session to;
            bool found;
            lock (_clientsLock) { found = _clients.TryGetValue(destKey, out to); }
            if (!found || to == null)
            {
                Send(from, Status("ERR|noroute"));
                return;
            }
            if (Send(to, BuildFrame(DerpFrame.TYPE_RECV_PACKET, delivery)))
                Interlocked.Increment(ref _framesRouted);
            else
                Send(from, Status("ERR|sendfailed"));
        }

        private static byte[] Status(string text)
        {
            return BuildFrame(DerpFrame.TYPE_SERVER_INFO, Encoding.UTF8.GetBytes(text));
        }

        private static string CleanKey(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            string s = raw.Trim();
            if (s.Length > 128) return "";
            foreach (char c in s)
            {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '#';
                if (!ok) return "";
            }
            return s;
        }

        private static bool Send(Session s, byte[] frame)
        {
            if (s == null || s.Stream == null) return false;
            try
            {
                lock (s.WriteLock)
                {
                    s.Stream.Write(frame, 0, frame.Length);
                    s.Stream.Flush();
                }
                return true;
            }
            catch { return false; }
        }

        private static bool ReadExact(Stream stream, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int n = stream.Read(buffer, offset + total, count - total);
                if (n <= 0) return false;
                total += n;
            }
            return true;
        }

        private static DerpFrame ReadFrame(Stream stream)
        {
            byte[] lenBuf = new byte[4];
            if (!ReadExact(stream, lenBuf, 0, 4)) return null;
            int len = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lenBuf, 0));
            if (len <= 0 || len > MaxFrameBytes) return null;
            byte[] body = new byte[len];
            if (!ReadExact(stream, body, 0, len)) return null;
            DerpFrame f = new DerpFrame();
            f.Type = body[0];
            f.Payload = new byte[len - 1];
            if (len > 1) Buffer.BlockCopy(body, 1, f.Payload, 0, len - 1);
            return f;
        }

        public static byte[] BuildFrame(byte type, byte[] payload)
        {
            int pLen = payload != null ? payload.Length : 0;
            byte[] frame = new byte[4 + 1 + pLen];
            int totalBodyLen = 1 + pLen;
            byte[] lenBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(totalBodyLen));
            Buffer.BlockCopy(lenBytes, 0, frame, 0, 4);
            frame[4] = type;
            if (pLen > 0) Buffer.BlockCopy(payload, 0, frame, 5, pLen);
            return frame;
        }

        public static bool ProbeDerpEndpoint(string host, int port, out int latencyMs)
        {
            latencyMs = -1;
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(2000)) return false;
                    client.EndConnect(ar);
                    sw.Stop();
                    latencyMs = (int)sw.ElapsedMilliseconds;
                    return true;
                }
            }
            catch { return false; }
        }
    }
}
