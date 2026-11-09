using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // Number leases: the relay remembering who a number belongs to.
    //
    // Why this exists. The relay has checked the number token all along - but
    // only against a session that happens to be connected right now. When the
    // owner is away there is no session, so there is nothing to compare against,
    // and any install that can reach the port can register your number and be
    // believed. Everything addressed to you then belongs to them: the mail that
    // queued while you were offline, incoming call invitations, and your entry in
    // other people's peer lists. The check was enforced whenever it was
    // inconvenient and skipped exactly when it mattered.
    //
    // A lease is the memory that makes the check permanent. First claim records
    // the number; the token is kept hashed, never as text; and a later claim with
    // a different token is refused even with the owner absent.
    //
    // Ownership, not rental. A token is a shared secret, so a lease that checks
    // only the secret proves "this caller knows the secret" - and whoever copies a
    // profile, or leans on the relay operator, knows it. The claim is therefore
    // anchored on the install's IDENTITY KEY: the registrant signs "OWNS|<number>"
    // and the relay verifies it with the key that made the signature, exactly the
    // way the PUBK directory proves a key belongs to a number. Once a lease has a
    // key on it, that key is the owner: a caller with the right token and a
    // different key is refused, because possessing a number now means possessing the
    // private half, and the record left on disk carries a signature anybody can
    // check instead of a hash only this relay's word about.
    //
    // What this is NOT, stated plainly:
    //   - It is not proof of identity to a trusted third party. Whoever registers
    //     an unclaimed number first holds it, and whoever runs the relay can delete
    //     this file. There is no key server to appeal to, because there is no server.
    //   - The operator can delete or replay records; they cannot forge one. Making a
    //     lease that a peer would accept for a number they do not hold needs the
    //     private key, so the file is checkable evidence, not a ledger to be edited.
    //     (Which is why a lease is not re-verified from disk on load: at ten thousand
    //     entries that is seconds of startup for a threat the same operator already
    //     covers by deleting the file. Signatures ARE checked on every registration.)
    //   - Losing identity.key means losing the number through the ordinary path: the
    //     operator has to release the lease, and the owner re-binds a new key. Peers
    //     will report a changed safety number, which is the correct thing for them to
    //     see, and the reason the release has to be a deliberate act.
    //   - A copied profile copies the key, so it copies the number. That is also how
    //     the wake agent is allowed to register the same number from the same profile.
    //
    // Escapes, because a lockout would be worse than the hole:
    //   - presenting the recorded key (with anything the operator allows) works;
    //   - `--serve --release-number=<num>` drops one lease deliberately;
    //   - deleting this file drops all of them, and the refusal message says so.
    // =====================================================================
    public sealed class NumberLeaseBook
    {
        public sealed class Lease
        {
            public string Number = "";
            public string TokenHash = "";
            public string IdentityPub = "";     // the owner: verified from a signature
            public string OwnSig = "";          // sig over "OWNS|<number>", by that key
            public string Machine = "";
            public long FirstSeen;
            public long LastSeen;
            public int FailedClaims;            // refusals since the owner last connected
        }

        readonly string _path;
        readonly object _lock = new object();
        readonly Dictionary<string, Lease> _leases = new Dictionary<string, Lease>();

        // The relay wires this to its log. A lease that cannot be written is a
        // number that becomes re-claimable at the next restart, so the failure has
        // to be heard - the bare `catch { }` this class used to have swallowed
        // exactly that, after answering the registration with OK.
        public Action<string> Warn;

        // A home relay on a private LAN serves a handful of people; a public one
        // maybe a few hundred. The ceiling is here so a hostile (or broken) client
        // cannot grow this file without bound, and hitting it refuses NEW claims -
        // existing owners are never evicted to make room.
        public const int MaxLeases = 10000;

        // Bound what one number may accumulate, so repeated attempts cannot grow
        // the file either. It is a counter, not a queue.
        const int FailedClaimCap = 999;

        public NumberLeaseBook(string path)
        {
            _path = path ?? "";
            Load();
        }

        public string Path { get { return _path; } }   // NB: fully qualify System.IO.Path inside this class

        public int Count { get { lock (_lock) return _leases.Count; } }

        public Lease Lookup(string number)
        {
            if (string.IsNullOrEmpty(number)) return null;
            lock (_lock)
            {
                Lease l;
                return _leases.TryGetValue(number, out l) ? l : null;
            }
        }

        public bool Has(string number) { return Lookup(number) != null; }

        // What the owner signs to prove the number is theirs. A different prefix from
        // the PUBK claim on purpose: the same key signs both, and a signature meant for
        // one must not be usable as the other.
        public static string OwnClaim(string number) { return "OWNS|" + (number ?? ""); }

        // The whole point: does this credential belong to the recorded owner?
        //
        // A key on the lease outranks a token, because a token is a secret two parties
        // both hold and a key is a secret only one holds. So a caller who copied a
        // config file but generated their own identity gets refused, and the recovery
        // path for a lost key is deliberate (release the lease), not automatic.
        // A lease with no key on it is a record from before this existed: the secret
        // still decides, until the owner's own registration binds a key.
        public bool Owns(Lease held, string token, string pub)
        {
            if (held == null) return true;                        // unowned: first claim wins
            if (!string.IsNullOrEmpty(held.IdentityPub)) return (pub ?? "") == held.IdentityPub;
            if (string.IsNullOrEmpty(held.TokenHash)) return true; // recorded with no secret to check
            return held.TokenHash == HashToken(token ?? "");
        }

        // Record or refresh a claim. Returns the number of refused attempts that
        // happened since this owner was last seen - the caller turns that into a
        // notice, because "three people tried to take your number overnight" is
        // information the owner should get, not something to bury in a log.
        public int Claim(string number, string token, string machine, string pub, string ownSig)
        {
            if (string.IsNullOrEmpty(number)) return 0;
            lock (_lock)
            {
                Lease l;
                if (!_leases.TryGetValue(number, out l))
                {
                    if (_leases.Count >= MaxLeases) return 0;
                    l = new Lease { Number = number, FirstSeen = DateTime.Now.Ticks };
                    _leases[number] = l;
                }
                int owed = l.FailedClaims;
                l.TokenHash = HashToken(token ?? "");
                if (!string.IsNullOrEmpty(pub)) { l.IdentityPub = pub; l.OwnSig = ownSig ?? ""; }
                if (!string.IsNullOrEmpty(machine)) l.Machine = machine;
                l.LastSeen = DateTime.Now.Ticks;
                l.FailedClaims = 0;
                Save();
                return owed;
            }
        }

        public void NoteFailedClaim(string number)
        {
            if (string.IsNullOrEmpty(number)) return;
            lock (_lock)
            {
                Lease l;
                if (!_leases.TryGetValue(number, out l)) return;
                if (l.FailedClaims < FailedClaimCap) l.FailedClaims++;
                Save();
            }
        }

        // Bind the identity key that a verified PUBK just proved possession of.
        // Kept separate from the token check on purpose: it is evidence for
        // humans to compare, not a second credential that can silently re-earn a
        // number, and a change here is reported rather than absorbed.
        // Returns: 0 = nothing to report, 1 = bound for the first time, 2 = changed.
        public int NoteIdentity(string number, string identityPub)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(identityPub)) return 0;
            lock (_lock)
            {
                Lease l;
                if (!_leases.TryGetValue(number, out l)) return 0;
                if (string.IsNullOrEmpty(l.IdentityPub))
                {
                    l.IdentityPub = identityPub;
                    Save();
                    return 1;
                }
                if (l.IdentityPub == identityPub) return 0;
                l.IdentityPub = identityPub;
                Save();
                return 2;
            }
        }

        public bool Release(string number)
        {
            if (string.IsNullOrEmpty(number)) return false;
            lock (_lock)
            {
                if (!_leases.ContainsKey(number)) return false;
                _leases.Remove(number);
                Save();
                return true;
            }
        }

        // sha256, hex. A lease file that leaked should not hand out the secrets
        // that re-register numbers, and the relay has no reason to ever need them
        // back in plain form.
        public static string HashToken(string token)
        {
            if (token == null) token = "";
            try
            {
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
                    StringBuilder sb = new StringBuilder(h.Length * 2);
                    for (int i = 0; i < h.Length; i++) sb.Append(h[i].ToString("x2", CultureInfo.InvariantCulture));
                    return sb.ToString();
                }
            }
            catch { return ""; }
        }

        // number|tokenHash|identityPub|ownSig|firstSeen|lastSeen|failedClaims|machine
        //
        // One line per lease. The free-text field is LAST and the split is bounded,
        // because a machine name is not ours to constrain: with the columns in the
        // other order a name containing a pipe shifted every field after it, the
        // numeric parses failed, and the record was dropped - which does not look
        // like a broken line, it looks like a number nobody owns. Base64 has no
        // pipes, so everything before the machine is safe to index.
        void Load()
        {
            try
            {
                if (_path.Length == 0 || !File.Exists(_path)) return;
                foreach (string ln in File.ReadAllLines(_path))
                {
                    if (string.IsNullOrEmpty(ln) || ln.Trim().Length == 0) continue;
                    string[] p = ln.Split(new char[] { '|' }, 8);
                    if (p.Length < 7) continue;              // unreadable shape: ignore it
                    string num = p[0].Trim();
                    if (!IsNumber(num)) continue;            // never trust what is on disk
                    Lease l = new Lease();
                    l.Number = num;
                    l.TokenHash = p[1].Trim();
                    l.IdentityPub = p[2];
                    l.OwnSig = p[3];
                    long ticks;
                    if (!long.TryParse(p[4], NumberStyles.None, CultureInfo.InvariantCulture, out ticks)) ticks = 0;
                    l.FirstSeen = ticks;
                    if (!long.TryParse(p[5], NumberStyles.None, CultureInfo.InvariantCulture, out ticks)) ticks = 0;
                    l.LastSeen = ticks;
                    int fails;
                    if (!int.TryParse(p[6], NumberStyles.None, CultureInfo.InvariantCulture, out fails)) fails = 0;
                    l.FailedClaims = fails;
                    l.Machine = p.Length >= 8 ? p[7] : "";   // whatever is left, pipes and all
                    lock (_lock) _leases[num] = l;
                }
            }
            catch { }
        }

        void Save()
        {
            if (_path.Length == 0) return;    // no path, nothing to persist
            // The folder is this book's own decision: a relay started against a
            // profile that has never been used has no directory yet, and the first
            // claim must still land. StateFile deliberately will not make one,
            // because that would resurrect a folder somebody just removed.
            try
            {
                string dir = System.IO.Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir) && !System.IO.Directory.Exists(dir))
                    System.IO.Directory.CreateDirectory(dir);
            }
            catch { }
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<string, Lease> kv in _leases)
            {
                Lease l = kv.Value;
                sb.Append(l.Number).Append('|').Append(l.TokenHash).Append('|').Append(l.IdentityPub).Append('|')
                  .Append(l.OwnSig).Append('|')
                  .Append(l.FirstSeen.ToString(CultureInfo.InvariantCulture)).Append('|')
                  .Append(l.LastSeen.ToString(CultureInfo.InvariantCulture)).Append('|')
                  .Append(l.FailedClaims.ToString(CultureInfo.InvariantCulture)).Append('|')
                  .Append(l.Machine ?? "").Append('\n');
            }
            // Written whole and swapped in, because a lease file caught half-written
            // is a file of numbers with no owners.
            if (!StateFile.WriteAtomic(_path, sb.ToString()))
            {
                Action<string> warn = Warn;
                if (warn != null)
                    warn("Number leases could not be written to " + _path +
                         " - a number claimed this session is not yet safe from a restart");
            }
        }

        static bool IsNumber(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4 || s.Length > 15) return false;
            for (int i = 0; i < s.Length; i++) if (s[i] < '0' || s[i] > '9') return false;
            return true;
        }
    }

    // =====================================================================
    // StateFile: the one way this relay puts a state file on disk - mail, the
    // peer key sheet, the number leases, the relay ledger.
    //
    // Writing the final path in place is wrong twice over. The writer holds the
    // file open with no sharing, so anything reading it at that moment throws;
    // and a crash half-way leaves a truncated file where a whole one was. For the
    // lease book a truncated file reads back as "fewer owners", which is the exact
    // hole that book exists to close. The ledger was the last file still written
    // in place, and a test reading it during a save took the whole process down
    // with an unhandled IOException.
    //
    // So the bytes go down beside the real file and are then swapped in. The swap
    // can still lose to a reader holding the file, and losing that race used to be
    // silent: a claim answered with OK and never written is a number that is
    // stealable again after a restart. So it is retried, and the caller is told.
    // =====================================================================
    static class StateFile
    {
        // One lock per folder, so the temp name can stay stable and writers of the
        // same sheet serialise - two connections saving one sheet at the same moment
        // would otherwise let one of them move the other's bytes into place.
        //
        // Deliberately not one lock for every state file: a single global lock makes a
        // slow swap on one relay stall every other relay in the process, and a retry
        // ladder of up to three tenths of a second per write turns that into a
        // multi-second wait for somebody else's mail. That version was tried, and it
        // showed up as a flaky disk assertion in the suite.
        //
        // Keyed by folder rather than by file, because mail is one file per message
        // and a lock per path would then be a lock per message - a table that grows
        // for as long as the relay runs, which is a leak dressed up as a fix. Folders
        // are few and stable; the extra serialisation between two messages in the
        // same queue is a few hundred bytes, which is less than the disk costs anyway.
        static readonly Dictionary<string, object> _pathLocks = new Dictionary<string, object>();
        static readonly object _pathsLock = new object();

        static object LockFor(string path)
        {
            string dir = System.IO.Path.GetDirectoryName(path) ?? "";
            lock (_pathsLock)
            {
                object o;
                if (!_pathLocks.TryGetValue(dir, out o)) { o = new object(); _pathLocks[dir] = o; }
                return o;
            }
        }

        public static bool WriteAtomic(string path, string text)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string part = path + ".part";
            try
            {
                lock (LockFor(path))
                {
                    // Deliberately does NOT create the parent folder. A state file
                    // belongs in a folder somebody decided to have - the profile home,
                    // or the mail queue, which makes itself before writing. Creating it
                    // here would resurrect a folder that was just removed, which turns
                    // a stopped relay into a permanent one and a test cleanup into a
                    // directory that reappears a second later. Missing folder, refused
                    // write, and the caller says so out loud: that is the honest order.
                    File.WriteAllText(part, text ?? "", Encoding.UTF8);
                    for (int attempt = 0; attempt < 6; attempt++)
                    {
                        if (Swap(part, path)) return true;
                        Thread.Sleep(20 * (attempt + 1));
                    }
                    try { if (File.Exists(part)) File.Delete(part); } catch { }
                }
            }
            catch { }
            return false;
        }

        // Read a state file without assuming nobody is writing it. A reader that
        // throws here is not having a bad day: in Identity.LoadOrGenerate the throw
        // was caught and answered with "mint a brand-new key", so a momentary lock
        // by the wake agent could quietly replace this device's identity - and every
        // peer's screen would show a first meeting instead of a warning. Retry, and
        // only then give up.
        public static string ReadShared(string path)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite))
                    using (StreamReader r = new StreamReader(fs, Encoding.UTF8))
                        return r.ReadToEnd();
                }
                catch (FileNotFoundException) { return null; }
                catch (IOException) { Thread.Sleep(40 * (attempt + 1)); }
                catch (UnauthorizedAccessException) { Thread.Sleep(40 * (attempt + 1)); }
            }
            return null;
        }

        static bool Swap(string part, string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    // Replace never leaves the path with no file behind it, which a
                    // reader can notice; delete-then-move can. It is refused on the
                    // filesystems without it (FAT on a stick, some SMB shares), so
                    // those fall back to the older pair of calls.
                    try { File.Replace(part, path, null); return true; }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                    File.Delete(path);
                }
                File.Move(part, path);
                return true;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }
    }
}
