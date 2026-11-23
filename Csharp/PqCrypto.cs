using System;
using System.Security.Cryptography;
using System.Text;

namespace UssdApp
{
    // =========================================================================
    // Post-quantum KEM API shape (EXPERIMENTAL PLACEHOLDER - NOT ML-KEM)
    //
    // This file is intentionally honest: it reserves the interface a real
    // FIPS 203 ML-KEM implementation would occupy, but the encapsulate and
    // decapsulate bodies are entropy/HMAC placeholders. They are NOT a lattice
    // KEM and must not be described as quantum-resistant in user-facing text.
    // Live call keys continue to come from the audited classical DH path in
    // VoipCrypto. DeriveHybridSessionKey is available for future integration
    // once a reviewed ML-KEM implementation is added.
    // =========================================================================

    public sealed class PqHybridKeyAgreement
    {
        public const bool IsProductionReady = false;

        private readonly byte[] _latticePrivateKey;
        public readonly byte[] LatticePublicKey;

        public PqHybridKeyAgreement()
        {
            // Placeholder byte layout matching the intended ML-KEM-768 API shape only.
            _latticePrivateKey = new byte[64];
            LatticePublicKey = new byte[1184];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(_latticePrivateKey);
                rng.GetBytes(LatticePublicKey);
            }
        }

        public byte[] Encapsulate(byte[] peerLatticePublicKey, out byte[] ciphertext)
        {
            if (peerLatticePublicKey == null || peerLatticePublicKey.Length == 0)
                throw new ArgumentNullException("peerLatticePublicKey");

            // Placeholder ciphertext of the intended ML-KEM-768 size.
            ciphertext = new byte[1088];
            byte[] sharedSecret = new byte[32];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ciphertext);
                rng.GetBytes(sharedSecret);
            }

            return sharedSecret;
        }

        public byte[] Decapsulate(byte[] ciphertext)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentNullException("ciphertext");

            // Placeholder HMAC only - not a KEM decapsulation operation.
            using (HMACSHA256 hmac = new HMACSHA256(_latticePrivateKey))
            {
                return hmac.ComputeHash(ciphertext);
            }
        }

        // Combines classical DH shared secret with post-quantum KEM shared secret
        public static byte[] DeriveHybridSessionKey(byte[] classicalDhSecret, byte[] pqKemSecret, string context)
        {
            if (classicalDhSecret == null) classicalDhSecret = new byte[0];
            if (pqKemSecret == null) pqKemSecret = new byte[0];

            byte[] ctxBytes = Encoding.UTF8.GetBytes(context ?? "USSD_PQ_HYBRID_V1");

            using (SHA256 sha = SHA256.Create())
            {
                byte[] combined = new byte[classicalDhSecret.Length + pqKemSecret.Length + ctxBytes.Length];
                int offset = 0;

                Buffer.BlockCopy(classicalDhSecret, 0, combined, offset, classicalDhSecret.Length);
                offset += classicalDhSecret.Length;

                Buffer.BlockCopy(pqKemSecret, 0, combined, offset, pqKemSecret.Length);
                offset += pqKemSecret.Length;

                Buffer.BlockCopy(ctxBytes, 0, combined, offset, ctxBytes.Length);

                return sha.ComputeHash(combined);
            }
        }
    }
}
