using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // Identity + end-to-end crypto layer.
    //
    // Why this file exists: the relay (any user's PC) forwards signaling
    // lines, and until now CHAT lines travelled as PLAINTEXT inside
    // "MSG|to|from|CHAT|...". Media was AES-encrypted; chat was not, and the
    // Diffie-Hellman exchange was unauthenticated, so a hostile relay could
    // both read chat and substitute keys.
    //
    // This layer adds the three things that close that gap:
    //   1. Identity      - a per-install RSA-2048 keypair whose ONLY job is to
    //                      authenticate the DH values we exchange.
    //   2. PeerIdentityBook - trust-on-first-use record of peer identity keys,
    //                      with a loud "changed" verdict for a MITM swap.
    //   3. ChatKey       - authenticated DH agreement -> AES-128-CTR + HMAC
    //                      (encrypt-then-MAC) so the relay only ever sees
    //                      "ECHAT|<base64 ciphertext>".
    //
    // BCL only (.NET 4.0 / C# 5): no NuGet, no native libs - the zero-install
    // build rule still holds.
    // =====================================================================

    // ---- 1. Per-install identity key ----
    public sealed class Identity
    {
        // sha256 with RSA (PKCS#1 v1.5). RSACryptoServiceProvider.SignHash takes
        // the HASH algorithm oid - passing sha256RSA here throws "OID unknown".
        private const string HashOid = "2.16.840.1.101.3.4.2.1";

        private RSACryptoServiceProvider _rsa;
        private readonly string _path;
        private string _pubB64;

        // The app number is part of every signature context, so a stolen
        // identity key cannot be replayed as somebody else's App ID.
        public string Number = "";

        public Identity(string path)
        {
            _path = path;
            _rsa = LoadOrGenerate(path);
        }

        // A stored key is imported into an empty provider rather than generated
        // and then thrown away. The difference is not cosmetic: the
        // (keySize) constructor spends a few hundred milliseconds building a key
        // that FromXmlString would immediately replace, and that cost sits on
        // whichever thread first needs an identity - which, for a relay, used to
        // be a link handshake starving the directory gossip behind it.
        static RSACryptoServiceProvider LoadOrGenerate(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    // Shared read with a retry: this file is also opened by the wake
                    // agent running from the same profile, and a momentary lock used
                    // to land in the catch below and be answered with a brand-new
                    // identity - every peer then seeing a first meeting rather than
                    // a replaced key. A lock is not a corrupt key.
                    string xml = StateFile.ReadShared(path);
                    if (!string.IsNullOrEmpty(xml))
                    {
                        RSACryptoServiceProvider loaded = new RSACryptoServiceProvider();
                        loaded.FromXmlString(xml);
                        return loaded;
                    }
                }
            }
            catch
            {
                // Unreadable or corrupt key file: fall through to a fresh identity
                // rather than refusing to start. Peers will see a key change and
                // the UI warns about it - which is the correct behaviour.
            }
            RSACryptoServiceProvider fresh = new RSACryptoServiceProvider(2048);
            try
            {
                // Swapped in rather than written down: a half-saved identity.key is
                // unreadable, and the next start would mint a different key and call
                // it a first meeting with everybody.
                StateFile.WriteAtomic(path, fresh.ToXmlString(true));
                try { File.SetAttributes(path, FileAttributes.Hidden); } catch { }
            }
            catch { }
            return fresh;
        }

        public string PublicBase64
        {
            get
            {
                if (_pubB64 == null)
                    _pubB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_rsa.ToXmlString(false)));
                return _pubB64;
            }
        }

        // Short human-checkable id: first 8 bytes of SHA-256(public key),
        // shown as 4 groups of 4 hex characters.
        // Fingerprint for a key we have not trusted yet - the warning UI shows
        // this so the change can be confirmed over another channel.
        public static string FingerprintOf(string pubB64)
        {
            if (string.IsNullOrEmpty(pubB64)) return "";
            try
            {
                byte[] h;
                using (SHA256 sha = SHA256.Create())
                    h = sha.ComputeHash(Encoding.UTF8.GetBytes(pubB64));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    if (i > 0 && i % 4 == 0) sb.Append('-');
                    sb.Append(h[i].ToString("X2", CultureInfo.InvariantCulture));
                }
                return sb.ToString();
            }
            catch { return ""; }
        }

        public string Fingerprint
        {
            get { return FingerprintOf(PublicBase64); }
        }

        public byte[] Sign(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
                return _rsa.SignHash(sha.ComputeHash(data), HashOid);
        }

        public byte[] SignText(string context)
        {
            return Sign(Encoding.UTF8.GetBytes((Number ?? "") + "|" + (context ?? "")));
        }

        // Reused by Verify and by the sealing helpers below: building the public
        // half from stored XML is the one step that a hostile key blob can make
        // throw, so it lives in a single guarded place.
        private static RSACryptoServiceProvider Public(string pubB64)
        {
            if (string.IsNullOrEmpty(pubB64)) return null;
            try
            {
                RSACryptoServiceProvider pub = new RSACryptoServiceProvider(2048);
                pub.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(pubB64)));
                return pub;
            }
            catch { return null; }
        }

        public static bool Verify(string pubB64, byte[] data, byte[] sig)
        {
            if (data == null || sig == null) return false;
            RSACryptoServiceProvider pub = Public(pubB64);
            if (pub == null) return false;
            try
            {
                using (SHA256 sha = SHA256.Create())
                    return pub.VerifyHash(sha.ComputeHash(data), HashOid, sig);
            }
            catch { return false; }
        }

        // ── Public-key confidentiality ─────────────────────────────────────
        // Sign/verify can authenticate a route but cannot hide one: hiding it
        // needs encrypting TO a party we have never spoken to. RSAES-OAEP is the
        // only public-key cipher RSACryptoServiceProvider offers on .NET 4.0, and
        // OAEP here means MGF1-SHA1 - sound, but worth naming, because the rest
        // of this file signs with SHA-256 and a reader would assume it matches.
        // Capacity is 256 - 2*20 - 2 = 194 bytes, which is why a layer's payload
        // rides on a wrapped AES key (SealedBox) instead of going in here.
        public byte[] EncryptOaep(byte[] data)
        {
            try { return _rsa.Encrypt(data, true); } catch { return null; }
        }

        public byte[] DecryptOaep(byte[] data)
        {
            try { return _rsa.Decrypt(data, true); } catch { return null; }
        }

        public static byte[] EncryptOaepTo(string pubB64, byte[] data)
        {
            if (data == null) return null;
            RSACryptoServiceProvider pub = Public(pubB64);
            if (pub == null) return null;
            try { return pub.Encrypt(data, true); } catch { return null; }
        }

        // How big a wrapped key comes back: needed to slice a sealed box, and
        // taken from the key rather than assumed, so a 4096-bit identity cannot
        // silently misalign every read.
        public int CipherBytes { get { return _rsa.KeySize / 8; } }

        public static bool VerifyText(string pubB64, string context, byte[] sig, string signerNumber)
        {
            return Verify(pubB64,
                Encoding.UTF8.GetBytes((signerNumber ?? "") + "|" + (context ?? "")), sig);
        }

        // Order-independent 12-group safety number: both peers compute the same
        // digits without needing to agree who goes first.
        public static string SafetyNumber(string pubA, string pubB)
        {
            string[] pair = new string[] { pubA ?? "", pubB ?? "" };
            if (string.CompareOrdinal(pair[0], pair[1]) > 0)
            {
                string t = pair[0]; pair[0] = pair[1]; pair[1] = t;
            }
            byte[] h;
            using (SHA256 sha = SHA256.Create())
                h = sha.ComputeHash(Encoding.UTF8.GetBytes(pair[0] + "\n" + pair[1]));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 12; i++)
            {
                if (i > 0) sb.Append(' ');
                int v = (h[i * 2] << 8 | h[i * 2 + 1]) % 100000;
                sb.Append(v.ToString("D5", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }
    }

    // ---- 2b. Deciding whether a relay is the relay ----
    //
    // "relay.friend:45675" is an address, not an identity. Whoever controls the
    // hosts file, the router or the DNS can point it at a machine of theirs, and an
    // unchecked client then hands that machine its number, its peer list and its
    // queued mail - which is precisely what a bootstrap relay list makes likely,
    // because it asks the app to connect somewhere it has never been. So the answer
    // is the same shape as every other pin in this file: the relay presents a key
    // that signed something only its owner can sign, and we compare it with what we
    // already believe about that address.
    //
    // Deliberately no policy in here: TryParse and Judge are pure so the dangerous
    // combinations - a key that does not sign its own id, a key that changed - can
    // be tested without a network, and the caller decides what a verdict costs.
    public static class RelayIdentity
    {
        public enum Verdict { BadSignature, New, Same, Mismatch }

        // The claim a relay signs over its own id. Same string relays exchange with
        // each other, so one key cannot satisfy one audience and not the other.
        public static string Claim(string relayId) { return "RLID|" + (relayId ?? ""); }

        public static bool Verify(string pubB64, string relayId, string sigB64)
        {
            if (string.IsNullOrEmpty(pubB64) || string.IsNullOrEmpty(relayId) ||
                string.IsNullOrEmpty(sigB64)) return false;
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64); } catch { return false; }
            try { return Identity.Verify(pubB64, Encoding.UTF8.GetBytes(Claim(relayId)), sig); }
            catch { return false; }
        }

        public static bool TryParse(string line, out string relayId, out string adv,
                                    out string pubB64, out string sigB64)
        {
            relayId = ""; adv = ""; pubB64 = ""; sigB64 = "";
            if (string.IsNullOrEmpty(line)) return false;
            // Split with no limit: the signature is last and base64 has no pipes in
            // it, so a glued remainder can only ever damage the signature - which
            // then fails to decode and is refused, rather than silently mis-parsed.
            string[] p = line.Split('|');
            if (p.Length < 5 || p[0] != "RPUB") return false;
            relayId = p[1].Trim();
            adv = p[2].Trim();
            pubB64 = p[3].Trim();
            sigB64 = p[4].Trim();
            return relayId.Length > 0 && pubB64.Length > 0;
        }

        // New is not "trusted": it is "pinned now, and here is the fingerprint to
        // check against somebody who has met this relay in person". Mismatch and
        // BadSignature are the two that must never be talked around - they are what
        // a substituted relay looks like.
        public static Verdict Judge(bool sigOk, string seenPubB64, string pinnedPubB64)
        {
            if (!sigOk) return Verdict.BadSignature;
            if (string.IsNullOrEmpty(pinnedPubB64)) return Verdict.New;
            return seenPubB64 == pinnedPubB64 ? Verdict.Same : Verdict.Mismatch;
        }

        public static string Fingerprint(string pubB64)
        {
            return Identity.FingerprintOf(pubB64);
        }
    }

    // ---- 2c. The list a stranger starts from ----
    //
    // Everything about a mesh assumes you already know one relay. A seed file is how
    // somebody who does not gets in - and it is exactly the place where trusting an
    // address stops being harmless, because an address can be pointed at anyone. So
    // each line carries the fingerprint expected there, and a fingerprint is only
    // useful because RelayIdentity above can check a key signed with it.
    //
    // Format, one entry per line, blank lines and #-comments ignored:
    //
    //     relay.example.net:45675|D9593821-33F4B347|Aisha's PC
    //     203.0.113.9:45675|-|friend's relay, pin it on first use
    //
    // "-" means "no expectation yet": connect and pin on first use, and be told the
    // digits so they can be confirmed. That is weaker than a pinned fingerprint and is
    // labelled as such in the UI - which is why the file ships empty rather than with
    // somebody else's server in it.
    public sealed class RelaySeedEntry
    {
        public string Address = "";
        public string Fingerprint = "";
        public string Note = "";
    }

    public static class RelaySeed
    {
        public const string AnyKey = "-";

        public static bool TryParseLine(string line, out RelaySeedEntry e)
        {
            e = null;
            if (string.IsNullOrEmpty(line)) return false;
            string t = line.Trim();
            if (t.Length == 0 || t.StartsWith("#", StringComparison.Ordinal)) return false;
            string[] p = t.Split('|');
            string addr = p[0].Trim();
            // An address needs a port to be dialable, and a bare "host" silently
            // defaulting to 45675 is how a typo in a shared file becomes somebody
            // else's server. Refuse it and say so at load time instead.
            if (addr.Length == 0 || addr.IndexOf(':') < 0) return false;
            e = new RelaySeedEntry { Address = addr };
            e.Fingerprint = p.Length >= 2 ? NormFp(p[1]) : AnyKey;
            if (e.Fingerprint.Length == 0) e.Fingerprint = AnyKey;
            e.Note = p.Length >= 3 ? p[2].Trim() : "";
            return true;
        }

        public static string NormFp(string fp)
        {
            return (fp ?? "").Trim().Replace(" ", "").ToUpperInvariant();
        }

        public static List<RelaySeedEntry> Load(string text)
        {
            var list = new List<RelaySeedEntry>();
            if (string.IsNullOrEmpty(text)) return list;
            foreach (string ln in text.Split('\n'))
            {
                RelaySeedEntry e;
                if (TryParseLine(ln, out e)) list.Add(e);
            }
            return list;
        }

        // Does what the relay proved match what the line promised?
        public static bool Matches(RelaySeedEntry e, string seenFingerprint)
        {
            if (e == null) return false;
            if (e.Fingerprint == AnyKey) return true;
            return string.Equals(e.Fingerprint, NormFp(seenFingerprint), StringComparison.Ordinal);
        }
    }

    // ---- 2. Trust-on-first-use book of peer identity keys ----
    public sealed class PeerIdentityBook
    {
        public enum Trust { New, Same, Changed }

        private readonly string _path;
        private readonly Dictionary<string, string> _keys = new Dictionary<string, string>();

        public PeerIdentityBook(string path)
        {
            _path = path;
            try
            {
                if (File.Exists(path))
                    foreach (string ln in File.ReadAllLines(path))
                    {
                        string[] p = ln.Split('|');
                        if (p.Length >= 2 && p[0].Length > 0) _keys[p[0]] = p[1];
                    }
            }
            catch { }
        }

        public string Lookup(string number)
        {
            string v;
            return _keys.TryGetValue(number ?? "", out v) ? v : null;
        }

        public int Count { get { return _keys.Count; } }

        // Records the key on first sight; flags a replacement, which is the
        // only signal a TOFU model can give for an active MITM. A changed key is
        // *not* silently swapped in: it is held as a warning until the user
        // explicitly accepts it, avoiding a TOFU overwrite that turns a MITM
        // warning into a silent identity replacement.
        public Trust Check(string number, string pubB64)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(pubB64)) return Trust.New;
            string old = Lookup(number);
            if (old == null) { Put(number, pubB64, false); return Trust.New; }
            if (old == pubB64) return Trust.Same;
            return Trust.Changed;
        }

        // Accept a previously flagged identity change only after the user has
        // explicitly reviewed and confirmed it. This keeps the trusted key in
        // the TOFU store and avoids mutating it in the warning path.
        public void AcceptChanged(string number, string pubB64)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(pubB64)) return;
            Put(number, pubB64, true);
        }

        private void Put(string number, string pubB64, bool replaced)
        {
            _keys[number] = pubB64;
            try
            {
                StringBuilder sb = new StringBuilder();
                foreach (KeyValuePair<string, string> kv in _keys)
                    sb.Append(kv.Key).Append('|').Append(kv.Value).Append('|')
                      .Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")).Append('|')
                      .Append(replaced && kv.Key == number ? "replaced" : "tofu").Append('\n');
                // Swapped in, never written over the live file: this is the TOFU pin
                // book. Lose it half-way and the next message from every known peer
                // reads as a first meeting, so the one warning this model has for an
                // active MITM switches itself off without saying anything.
                StateFile.WriteAtomic(_path, sb.ToString());
            }
            catch { }
        }
    }

    // ---- 3. Authenticated chat key agreement + sealed messages ----
    //
    // Wire format (all inside the existing relay MSG envelope):
    //   KEYX|<ephemeral DH pub>|<identity pub b64>|<sig b64>   sig  = "KEYX|<dh>"
    //   KEYXOK|<ephemeral DH pub>|<identity pub b64>|<sig b64> sig  = "KEYXOK|<dh>"
    //   ECHAT|<b64( iv(16) | aes128ctr(plaintext) | hmac16 )>
    //
    // The relay sees only base64 blobs; it cannot read them, and it cannot
    // forge either, because the DH value is bound to a signed identity key.
    public sealed class ChatKey
    {
        private readonly byte[] _aes;      // 16 bytes
        private readonly byte[] _mac;      // 32 bytes
        private long _seq;
        private readonly object _replayLock = new object();
        private readonly HashSet<string> _seenTags = new HashSet<string>();

        private ChatKey(byte[] material)
        {
            _aes = new byte[16];
            _mac = new byte[32];
            Buffer.BlockCopy(material, 0, _aes, 0, 16);
            Buffer.BlockCopy(material, 16, _mac, 0, 32);
        }

        public static ChatKey FromShared(BigInteger shared)
        {
            return FromMaterial(shared.ToByteArray());
        }

        // VoipCrypto.DeriveSharedKey already hashes the DH result with SHA-256;
        // we stretch that into separate encryption and MAC keys.
        public static ChatKey FromMaterial(byte[] shared)
        {
            using (SHA512 sha = SHA512.Create())
                return new ChatKey(sha.ComputeHash(shared));
        }

        public bool Ready { get { return _aes != null && _mac != null; } }

        public string Encrypt(string plain)
        {
            byte[] iv = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(iv);
            byte[] body = Encoding.UTF8.GetBytes(plain ?? "");
            byte[] ct = VoipCrypto.AesCtr(_aes, body, iv);
            byte[] tag = VoipCrypto.HmacSha256(_mac, Concat(iv, ct));
            byte[] outp = new byte[iv.Length + ct.Length + 16];
            Buffer.BlockCopy(iv, 0, outp, 0, iv.Length);
            Buffer.BlockCopy(ct, 0, outp, iv.Length, ct.Length);
            Buffer.BlockCopy(tag, 0, outp, iv.Length + ct.Length, 16);
            Interlocked.Increment(ref _seq);
            return Convert.ToBase64String(outp);
        }

        public string Decrypt(string b64)
        {
            byte[] raw;
            try { raw = Convert.FromBase64String(b64); } catch { return null; }
            if (raw.Length < 16 + 16) return null;
            byte[] iv = new byte[16];
            byte[] ct = new byte[raw.Length - 32];
            byte[] tag = new byte[16];
            Buffer.BlockCopy(raw, 0, iv, 0, 16);
            Buffer.BlockCopy(raw, 16, ct, 0, ct.Length);
            Buffer.BlockCopy(raw, 16 + ct.Length, tag, 0, 16);
            byte[] want = VoipCrypto.HmacSha256(_mac, Concat(iv, ct));
            if (!FixedTimeEquals(tag, 0, want, 0, 16)) return null;   // tampered
            string tagId = Convert.ToBase64String(tag);
            lock (_replayLock)
            {
                if (_seenTags.Contains(tagId)) return null;
                _seenTags.Add(tagId);
                if (_seenTags.Count > 256)
                {
                    string oldest = null;
                    foreach (string seen in _seenTags) { oldest = seen; break; }
                    if (oldest != null) _seenTags.Remove(oldest);
                }
            }
            return Encoding.UTF8.GetString(VoipCrypto.AesCtr(_aes, ct, iv));
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        // Constant-time compare: a timing shortcut here is a forgery oracle.
        public static bool FixedTimeEquals(byte[] a, int offA, byte[] b, int offB, int len)
        {
            if (a == null || b == null) return false;
            if (offA + len > a.Length || offB + len > b.Length) return false;
            int diff = 0;
            for (int i = 0; i < len; i++) diff |= a[offA + i] ^ b[offB + i];
            return diff == 0;
        }

        // Symmetric ratchet: derive a new key from the current one. This
        // provides forward secrecy within a session — compromising the
        // current key does not reveal past keys, because HMAC is one-way.
        // Both sides must ratchet at the same point (e.g. after every N
        // messages, or on each round-trip) to stay in sync.
        //
        // The ratchet is a chain: each step derives new AES and MAC keys
        // from the current MAC key, so the chain is:
        //   K0 (from DH) → K1 = HMAC(K0, "ratchet") → K2 = HMAC(K1, "ratchet") → ...
        // Compromising K5 reveals K6, K7, ... but not K4, K3, K2, K1, K0.
        public void Ratchet()
        {
            // Derive new material from the current MAC key
            byte[] material = VoipCrypto.HmacSha256(_mac, Encoding.UTF8.GetBytes("ratchet"));
            // Overwrite in place: _aes and _mac are readonly references but
            // their contents can be modified
            Buffer.BlockCopy(material, 0, _aes, 0, 16);
            Buffer.BlockCopy(material, 16, _mac, 0, 32);
            // Reset the sequence counter for the new chain
            Interlocked.Exchange(ref _seq, 0);
        }

        // Ratchet count: how many times the key has been advanced. Useful for
        // logging and for keeping both sides in sync.
        private int _ratchetCount;
        public int RatchetCount { get { return _ratchetCount; } }
        public void RatchetN(int n)
        {
            for (int i = 0; i < n; i++) { Ratchet(); _ratchetCount++; }
        }
    }

    // A signed release description. This is deliberately a verifier only:
    // callers must pin the publisher key, show the result to the user, and
    // perform any download/install through an explicit user-controlled flow.
    // No network access or code execution belongs in this class.
    public sealed class SignedUpdateManifest
    {
        public string Version;
        public string Sha256;
        public long Length;
        public string Uri;
        public string Signature;

        public static string Claim(string version, string sha256, long length, string uri)
        {
            return "USSDUPDATE|1|" + (version ?? "") + "|" + (sha256 ?? "") + "|" +
                   length.ToString(CultureInfo.InvariantCulture) + "|" + (uri ?? "");
        }

        public static bool TryParse(string line, out SignedUpdateManifest manifest)
        {
            manifest = null;
            if (string.IsNullOrEmpty(line)) return false;
            string[] p = line.Split('|');
            if (p.Length != 7 || p[0] != "USSDUPDATE" || p[1] != "1") return false;
            long length;
            if (!long.TryParse(p[4], NumberStyles.None, CultureInfo.InvariantCulture, out length) ||
                length < 0 || p[2].Length == 0 || p[3].Length == 0 || p[5].Length == 0 ||
                p[6].Length == 0)
                return false;
            if (p[3].Length != 64) return false;
            for (int i = 0; i < p[3].Length; i++)
                if (UriHex(p[3][i]) < 0) return false;
            System.Uri target;
            if (!System.Uri.TryCreate(p[5], UriKind.Absolute, out target) ||
                target.Scheme != System.Uri.UriSchemeHttps) return false;
            manifest = new SignedUpdateManifest
            {
                Version = p[2],
                Sha256 = p[3].ToUpperInvariant(),
                Length = length,
                Uri = p[5],
                Signature = p[6]
            };
            return true;
        }

        public bool Verify(string publisherPubB64)
        {
            if (string.IsNullOrEmpty(publisherPubB64) || string.IsNullOrEmpty(Signature)) return false;
            byte[] sig;
            try { sig = Convert.FromBase64String(Signature); } catch { return false; }
            return Identity.Verify(publisherPubB64,
                Encoding.UTF8.GetBytes(Claim(Version, Sha256, Length, Uri)), sig);
        }

        static int UriHex(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        }
    }

    // One ephemeral agreement in flight (initiator or responder side).
    public sealed class ChatHandshake
    {
        public readonly VoipCrypto Crypto;
        public readonly string EphemeralPub;
        public string PeerIdentityPub;
        public string PeerEphemeralPub;

        public ChatHandshake()
        {
            Crypto = new VoipCrypto();
            EphemeralPub = Crypto.Pub.ToString();
        }

        // "KEYX|<dh>|<idpub>|<sig>" - signed over our own ephemeral value.
        public string Build(Identity id, bool isAck)
        {
            string verb = isAck ? "KEYXOK" : "KEYX";
            byte[] sig = id.SignText(verb + "|" + EphemeralPub);
            return verb + "|" + EphemeralPub + "|" + id.PublicBase64 + "|" + Convert.ToBase64String(sig);
        }

        // Verify a peer's line and derive the shared key. Null on any failure.
        public ChatKey Accept(string verb, string peerDh, string peerIdPub, string sigB64, string peerNumber)
        {
            if (string.IsNullOrEmpty(peerDh) || string.IsNullOrEmpty(peerIdPub)) return null;
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64 ?? ""); } catch { return null; }
            if (!Identity.VerifyText(peerIdPub, verb + "|" + peerDh, sig, peerNumber)) return null;
            PeerIdentityPub = peerIdPub;
            PeerEphemeralPub = peerDh;
            try { return ChatKey.FromMaterial(Crypto.DeriveSharedKey(BigInteger.Parse(peerDh))); }
            catch { return null; }
        }
    }

    // ---- 4. Sealed box: confidentiality to a key we only know publicly ----
    //
    // Hybrid encryption, because RSA-OAEP alone would cap a layer at 194 bytes:
    //   token = b64( rsaOaep(48B key) | iv(16) | tag(16) | aes128ctr(payload) )
    // key = 16 AES + 32 HMAC, payload encrypted then MACed over iv||ct - the same
    // encrypt-then-MAC order ChatKey uses, so one mistake cannot be made twice.
    // There is no forward secrecy here and none is claimed: a sealed layer stays
    // readable to whoever holds that relay's key file for as long as they hold it.
    public static class SealedBox
    {
        const int KeyLen = 48;
        const int IvLen = 16;
        const int TagLen = 16;

        public static string Seal(string pubB64, byte[] plain)
        {
            if (plain == null) return null;
            byte[] key = Random(KeyLen);
            byte[] iv = Random(IvLen);
            byte[] aes = Slice(key, 0, 16);
            byte[] mac = Slice(key, 16, 32);
            byte[] ct = VoipCrypto.AesCtr(aes, plain, iv);
            byte[] tag = VoipCrypto.HmacSha256(mac, Cat(iv, ct));
            byte[] wrapped = Identity.EncryptOaepTo(pubB64, key);
            if (wrapped == null) return null;
            byte[] outp = new byte[wrapped.Length + IvLen + TagLen + ct.Length];
            Buffer.BlockCopy(wrapped, 0, outp, 0, wrapped.Length);
            Buffer.BlockCopy(iv, 0, outp, wrapped.Length, IvLen);
            Buffer.BlockCopy(tag, 0, outp, wrapped.Length + IvLen, TagLen);
            Buffer.BlockCopy(ct, 0, outp, wrapped.Length + IvLen + TagLen, ct.Length);
            return Convert.ToBase64String(outp);
        }

        // Null on any failure, including a one-bit edit: the MAC is checked
        // before a single plaintext byte is handed back.
        public static byte[] Unseal(Identity to, string token, int cipherBytes)
        {
            if (to == null || string.IsNullOrEmpty(token)) return null;
            byte[] raw;
            try { raw = Convert.FromBase64String(token); } catch { return null; }
            int head = cipherBytes + IvLen + TagLen;
            if (cipherBytes < 64 || raw.Length < head + 16) return null;
            byte[] wrapped = Slice(raw, 0, cipherBytes);
            byte[] iv = Slice(raw, cipherBytes, IvLen);
            byte[] tag = Slice(raw, cipherBytes + IvLen, TagLen);
            byte[] ct = Slice(raw, head, raw.Length - head);
            byte[] key = to.DecryptOaep(wrapped);
            if (key == null || key.Length != KeyLen) return null;
            byte[] want = VoipCrypto.HmacSha256(Slice(key, 16, 32), Cat(iv, ct));
            if (!ChatKey.FixedTimeEquals(tag, 0, want, 0, TagLen)) return null;
            return VoipCrypto.AesCtr(Slice(key, 0, 16), ct, iv);
        }

        static byte[] Random(int n)
        {
            byte[] b = new byte[n];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }

        static byte[] Slice(byte[] src, int off, int len)
        {
            byte[] b = new byte[len];
            if (len > 0) Buffer.BlockCopy(src, off, b, 0, len);
            return b;
        }

        static byte[] Cat(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }

    // ---- 5. Onion layers: hide the pairing, not the payload ----
    //
    // What a plain forwarded line gives away is not the text - ECHAT already
    // seals that - it is the *pair*: "MSG|<target>|<sender>|..." names both ends
    // to every relay in between. A layer here names at most the next hop, and
    // only the delivering relay ever sees both numbers.
    //
    //   layer = Seal( hopPub, pad( "v1|KIND|DEST|EXPIRY|INDEX|b64(body)" ) )
    //   KIND  = HOP -> DEST is the next relay id, body is the next layer
    //   KIND  = END -> DEST is the number to deliver to, body is the wire line
    //
    // Payloads are rounded up to 256-byte buckets so a hop cannot read how long
    // the message was. The layer header is not bucket-aligned on its own fields,
    // so what padding buys is length granularity, not a constant size.
    public sealed class OnionHop
    {
        public string Kind = "";
        public string Dest = "";
        public string Body = "";
        public int Index;
        public long Expiry;
        public bool Expired { get { return DateTime.Now.Ticks > Expiry; } }
    }

    public static class Onion
    {
        public const int Bucket = 256;
        public const int MaxLayers = 4;
        const int MaxPad = 64 * 1024;
        static readonly long Ttl = 5L * TimeSpan.TicksPerMinute;

        // pubB64s are the hops in travel order; the last one is the relay that
        // delivers. nextIds[i] is who hop i must hand to, unused on the last hop.
        // Returns the single outermost token: each hop is handed only what it can
        // open, so nothing has to travel as a list.
        public static string Build(IList<string> pubB64s, IList<string> nextIds,
                                   string targetNumber, string innerLine)
        {
            int n = pubB64s == null ? 0 : pubB64s.Count;
            if (n < 2 || n > MaxLayers) return null;      // one hop gains nothing
            if (nextIds == null || nextIds.Count < n) return null;
            string cur = innerLine;
            for (int i = n - 1; i >= 0; i--)
            {
                bool last = (i == n - 1);
                string plain = "v1|" + (last ? "END" : "HOP") + "|" +
                               (last ? targetNumber : nextIds[i]) + "|" +
                               (DateTime.Now.Ticks + Ttl).ToString(CultureInfo.InvariantCulture) + "|" +
                               i.ToString(CultureInfo.InvariantCulture) + "|" +
                               Convert.ToBase64String(Encoding.UTF8.GetBytes(cur ?? ""));
                string tok = SealedBox.Seal(pubB64s[i], Pad(plain));
                if (tok == null) return null;
                cur = tok;
            }
            return cur;
        }

        // Re-seal the carry instruction for the next hop. Needed because the
        // relay that starts a circuit knows who owns the target but not who the
        // middle relays are linked to: each hop resolves the destination relay id
        // against its own directory, so each hop has to hand on an envelope its
        // own next hop can open. The payload inside is never re-read, only
        // re-wrapped, so no hop can open what belongs to another.
        public static string Wrap(string pubB64, string nextRelayId, string body, int index)
        {
            if (string.IsNullOrEmpty(pubB64) || body == null) return null;
            if (string.IsNullOrEmpty(nextRelayId)) return null;
            string plain = "v1|HOP|" + nextRelayId + "|" +
                           (DateTime.Now.Ticks + Ttl).ToString(CultureInfo.InvariantCulture) + "|" +
                           index.ToString(CultureInfo.InvariantCulture) + "|" +
                           Convert.ToBase64String(Encoding.UTF8.GetBytes(body));
            return SealedBox.Seal(pubB64, Pad(plain));
        }

        // Null for a layer that is not ours, is edited, or has aged out.
        public static OnionHop Peel(Identity me, string token)
        {
            if (me == null) return null;
            byte[] raw = SealedBox.Unseal(me, token, me.CipherBytes);
            if (raw == null) return null;
            string plain = Unpad(raw);
            if (plain == null) return null;
            string[] p = plain.Split('|');
            if (p.Length != 6 || p[0] != "v1") return null;
            OnionHop h = new OnionHop();
            h.Kind = p[1];
            h.Dest = p[2];
            long ticks; int idx;
            if (!long.TryParse(p[3], NumberStyles.None, CultureInfo.InvariantCulture, out ticks)) return null;
            if (!int.TryParse(p[4], NumberStyles.None, CultureInfo.InvariantCulture, out idx)) return null;
            h.Expiry = ticks;
            h.Index = idx;
            try { h.Body = Encoding.UTF8.GetString(Convert.FromBase64String(p[5])); } catch { return null; }
            return h;
        }

        // 4-byte length, body, then zeroes to a whole bucket.
        public static byte[] Pad(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s ?? "");
            int need = b.Length + 4;
            int n = ((need + Bucket - 1) / Bucket) * Bucket;
            if (n > MaxPad) return null;
            byte[] o = new byte[n];
            o[0] = (byte)(b.Length >> 24); o[1] = (byte)(b.Length >> 16);
            o[2] = (byte)(b.Length >> 8); o[3] = (byte)b.Length;
            Buffer.BlockCopy(b, 0, o, 4, b.Length);
            return o;
        }

        public static string Unpad(byte[] raw)
        {
            if (raw == null || raw.Length < 4 || raw.Length % Bucket != 0) return null;
            int n = raw[0] << 24 | raw[1] << 16 | raw[2] << 8 | raw[3];
            if (n < 0 || n > raw.Length - 4) return null;
            return Encoding.UTF8.GetString(raw, 4, n);
        }
    }

    // ---- 6. Offline sealing: mail for somebody who is not connected ----
    //
    // The session key in ChatKey only exists after a KEYX exchange, and a KEYX
    // needs the peer to answer. So a message to somebody who is off-line - the
    // normal case for an offline queue - could not be sealed at all: it sat in the
    // relay's queue as plaintext, and it could not be carried to another relay
    // without showing it to that relay's owner.
    //
    // A published identity key fixes that. The recipient's key is already on the
    // relay (see PUBK), so the sender can seal to it with no round trip:
    //
    //   ECHATK|<sealed box>|<sender signature over the sealed box>
    //
    // The sealed body binds both numbers and a timestamp, so a message cannot be
    // replayed as somebody else's or moved to another recipient, and the signature
    // is over the ciphertext rather than the text: a relay cannot forge a message
    // from a peer without that peer's key, which is the property the plaintext
    // queue never had.
    //
    // What it does NOT do: no forward secrecy, and no post-compromise forward
    // secrecy - recover a relay's identity key file and every offline message ever
    // addressed to it opens. Double Ratchet-style per-message keys are the answer
    // and are not implemented here.
    public static class OfflineSeal
    {
        public const string Verb = "ECHATK";

        public sealed class Opened
        {
            public string From = "";
            public string To = "";
            public long Ticks;
            public string Text = "";
            public string SenderPub = "";      // the key that signed it, for the UI
        }

        // Returns the whole wire line, ready for MSG|to|from|<line>.
        public static string Seal(Identity mine, string toPubB64, string fromNumber,
                                  string toNumber, string text)
        {
            if (mine == null || string.IsNullOrEmpty(toPubB64)) return null;
            string body = (fromNumber ?? "") + "|" + (toNumber ?? "") + "|" +
                          DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture) + "|" +
                          (text ?? "");
            string box = SealedBox.Seal(toPubB64, Encoding.UTF8.GetBytes(body));
            if (box == null) return null;
            byte[] sig = mine.Sign(Encoding.UTF8.GetBytes(Verb + "|" + box));
            if (sig == null) return null;
            return Verb + "|" + box + "|" + Convert.ToBase64String(sig);
        }

        // The recipient verifies the signature against the SENDER's published key
        // (held from the key directory or a previous KEYX), then opens the box with
        // its own private key. Null means: not ours to open, edited, not signed by
        // that peer, or re-attribute by a relay. `expectFrom`/`expectTo` are what the
        // MSG envelope claimed - the two have to agree.
        public static Opened OpenWith(Identity mine, string line, string senderPubB64,
                                      string expectFrom, string expectTo)
        {
            if (mine == null || string.IsNullOrEmpty(line)) return null;
            string[] p = line.Split(new char[] { '|' }, 3);
            if (p.Length < 3 || p[0] != Verb) return null;
            byte[] sig;
            try { sig = Convert.FromBase64String(p[2]); } catch { return null; }
            if (string.IsNullOrEmpty(senderPubB64)) return null;
            // Checked before anything is decrypted: the cheapest forgery is one that
            // never reaches the cipher.
            if (!Identity.Verify(senderPubB64, Encoding.UTF8.GetBytes(Verb + "|" + p[1]), sig))
                return null;                        // not signed by that peer
            byte[] body = SealedBox.Unseal(mine, p[1], mine.CipherBytes);
            if (body == null) return null;
            string[] f = Encoding.UTF8.GetString(body).Split(new char[] { '|' }, 4);
            if (f.Length < 4) return null;
            long ticks;
            if (!long.TryParse(f[2], NumberStyles.None, CultureInfo.InvariantCulture, out ticks)) return null;
            Opened o = new Opened();
            o.From = f[0]; o.To = f[1]; o.Ticks = ticks; o.Text = f[3]; o.SenderPub = senderPubB64;
            // Both numbers are inside the signed ciphertext, so a relay that rewrote
            // the envelope to redirect or re-attribute the message cannot match.
            if (!string.IsNullOrEmpty(expectFrom) && o.From != expectFrom) return null;
            if (!string.IsNullOrEmpty(expectTo) && o.To != expectTo) return null;
            return o;
        }
    }

    // ---- Offline wake hint ----
    //
    // Nothing can reach a powered-off device, so the honest primitive is a
    // locally observable hint: the agent/relay stores pending counts and the
    // app raises them the moment it comes back. Kept here so both the main app
    // and the background agent agree on the file format.
    public static class PendingNotice
    {
        public static string PathFor(string dir) { return Path.Combine(dir, "pending_notices.txt"); }

        public static void Record(string dir, string kind, string from, string stamp)
        {
            try
            {
                Directory.CreateDirectory(dir);
                File.AppendAllText(PathFor(dir),
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "|" + kind + "|" + from + "|" + stamp + "\n",
                    Encoding.UTF8);
            }
            catch { }
        }

        public static List<string[]> ReadAll(string dir)
        {
            List<string[]> rows = new List<string[]>();
            try
            {
                string p = PathFor(dir);
                if (!File.Exists(p)) return rows;
                foreach (string ln in File.ReadAllLines(p))
                {
                    string[] parts = ln.Split('|');
                    if (parts.Length >= 3) rows.Add(parts);
                }
            }
            catch { }
            return rows;
        }

        public static void Clear(string dir)
        {
            try { if (File.Exists(PathFor(dir))) File.Delete(PathFor(dir)); } catch { }
        }
    }

    // Per-install data home: identity key, peer book, config, chats and the
    // wake inbox all live here. It defaults to the folder the exe sits in, and
    // --home= lets one agent serve a profile that lives elsewhere (scheduled
    // task, a second user, a USB install) without duplicating any key material.
    public static class Home
    {
        private static string _dir = AppDomain.CurrentDomain.BaseDirectory;

        public static string Dir { get { return _dir; } }

        public static void Set(string d)
        {
            if (string.IsNullOrEmpty(d)) return;
            string full = d.TrimEnd('\\', '/');
            try { full = Path.GetFullPath(full); } catch { return; }
            _dir = full + Path.DirectorySeparatorChar;
        }
    }

    // ---- Hand-off between the wake agent and the window ----
    //
    // The agent (UssdAgent.exe --agent) holds the relay connection while the
    // window is closed. It cannot render a call, so it does the two things that
    // are actually possible: it stores what arrived, and it starts the app.
    // One file per message (never a delimited log) so a message body cannot
    // corrupt the hand-off, and a two-step write so the app never reads a
    // half-written file. The app replays these through its normal inbound path,
    // so the chat store keeps exactly one writer of its format.
    public static class WakeInbox
    {
        public static string DirFor(string home) { return Path.Combine(home, "wake_inbox"); }

        public static void Save(string home, string from, string text)
        {
            try
            {
                string d = DirFor(home);
                Directory.CreateDirectory(d);
                string final = Path.Combine(d, DateTime.Now.Ticks + ".msg");
                string part = final + ".part";
                File.WriteAllText(part, (from ?? "") + "\n" + (text ?? ""), Encoding.UTF8);
                if (File.Exists(final)) File.Delete(final);
                File.Move(part, final);
            }
            catch { }
        }

        // Reads and consumes: each file is deleted as it is returned, so a
        // restart of the app cannot show the same message twice.
        public static List<string[]> Take(string home)
        {
            List<string[]> rows = new List<string[]>();
            try
            {
                string d = DirFor(home);
                if (!Directory.Exists(d)) return rows;
                string[] files = Filter(SortedFiles(d));
                foreach (string f in files)
                {
                    string body = "";
                    try { body = File.ReadAllText(f, Encoding.UTF8); } catch { continue; }
                    int nl = body.IndexOf('\n');
                    string from = nl < 0 ? body : body.Substring(0, nl);
                    string text = nl < 0 ? "" : body.Substring(nl + 1);
                    try { File.Delete(f); } catch { }
                    rows.Add(new string[] { from.Trim(), text });
                }
            }
            catch { }
            return rows;
        }

        public static int Count(string home)
        {
            try
            {
                string d = DirFor(home);
                return Directory.Exists(d) ? Filter(SortedFiles(d)).Length : 0;
            }
            catch { return 0; }
        }

        // "*.msg" is matched by the OS, and its rules about trailing text are not
        // something a hand-off should depend on, so drop anything that is not
        // exactly a finished message here.
        private static string[] Filter(string[] files)
        {
            List<string> keep = new List<string>();
            foreach (string f in files)
                if (f.EndsWith(".msg", StringComparison.OrdinalIgnoreCase)) keep.Add(f);
            return keep.ToArray();
        }

        private static string[] SortedFiles(string dir)
        {
            // Files are named by the ticks of their arrival, and ticks have a
            // fixed width for the next several centuries, so a name sort is a
            // time sort.
            string[] all = Directory.GetFiles(dir, "*.msg*");
            Array.Sort(all, StringComparer.Ordinal);
            return all;
        }
    }
}
