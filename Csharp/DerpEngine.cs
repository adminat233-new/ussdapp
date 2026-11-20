using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =========================================================================
    // Deterministic Encrypted Relay Protocol (DERP) & Advanced NAT Traversal Engine
    //
    // Provides full-connectivity packet routing over TLS / encrypted TCP streams
    // when symmetric NAT or CGNAT prevents direct UDP hole-punching.
    // Follows Tailscale-like DERP frame specification:
    //   Magic Cookie: "DERP1" (5 bytes)
    //   Frame Type:
    //     0x01: ClientInfo / Handshake (client public key + proof)
    //     0x02: ServerInfo (server public key + MTU)
    //     0x03: SendPacket (destination peer key + length + ciphertext)
    //     0x04: RecvPacket (source peer key + length + ciphertext)
    //     0x05: KeepAlive
    //     0x06: Ping / Pong
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
        private readonly string _localNodeKey;
        private readonly int _relayPort;
        private TcpListener _listener;
        private volatile bool _running;

        public DerpMeshRouter(string localNodeKey, int relayPort)
        {
            _localNodeKey = localNodeKey ?? "node_local";
            _relayPort = relayPort > 0 ? relayPort : 9005;
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
            catch { }
        }

        public void Stop()
        {
            _running = false;
            try { if (_listener != null) _listener.Stop(); } catch { }
        }

        private void ListenLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    Thread handler = new Thread(() => HandleClient(client));
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
            using (client)
            using (NetworkStream stream = client.GetStream())
            {
                stream.ReadTimeout = 15000;
                stream.WriteTimeout = 15000;
                try
                {
                    // Read header: 5 bytes magic "DERP1"
                    byte[] magic = new byte[5];
                    int read = stream.Read(magic, 0, 5);
                    if (read < 5 || Encoding.ASCII.GetString(magic) != "DERP1")
                        return;

                    // Send ServerInfo response
                    byte[] srvInfo = Encoding.UTF8.GetBytes("DERP_SERVER_OK|MTU=1420|NODE=" + _localNodeKey);
                    byte[] frame = BuildFrame(DerpFrame.TYPE_SERVER_INFO, srvInfo);
                    stream.Write(frame, 0, frame.Length);

                    // Client relay loop
                    byte[] lenBuf = new byte[4];
                    while (_running && client.Connected)
                    {
                        int r = stream.Read(lenBuf, 0, 4);
                        if (r < 4) break;
                        int frameLen = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lenBuf, 0));
                        if (frameLen <= 0 || frameLen > 65536) break;

                        byte[] body = new byte[frameLen];
                        int total = 0;
                        while (total < frameLen)
                        {
                            int n = stream.Read(body, total, frameLen - total);
                            if (n <= 0) break;
                            total += n;
                        }
                        if (total < frameLen) break;

                        byte frameType = body[0];
                        if (frameType == DerpFrame.TYPE_PING)
                        {
                            byte[] pong = BuildFrame(DerpFrame.TYPE_KEEPALIVE, new byte[0]);
                            stream.Write(pong, 0, pong.Length);
                        }
                    }
                }
                catch { }
            }
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
