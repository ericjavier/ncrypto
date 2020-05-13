using NCrypto.Common;
using NCrypto.Cryptography.Hashes;
using System;

using static NCrypto.Cryptography.Signatures.HashBased.LamportHelper;

namespace NCrypto.Cryptography.Signatures.HashBased
{
    /// <summary>
    /// h: X -> Y (one way only)
    /// y: R -> Y (random)
    /// ms = [m1, m2, ..., mk] // mi = { 0 | 1 }
    /// sk = [sk0, sk1]
    ///    = [y(0, 1), y(0, 2), ..., y(0, k), y(1, 1), y(1, 2), ..., y(1, k)]
    /// pk = [pk0, pk1]
    ///    = [z(0, 1), z(0, 2), ..., z(0, k), z(1, 1), z(1, 2), ..., z(1, k)]
    ///    = [h(y(0, 1)), h(y(0, 2)), ..., h(y(0, k)), h(y(1, 1)), h(y(1, 2)), ..., h(y(1, k))]
    /// sg = [s1, s2, ..., sk]
    ///    = [y(m1, 1), y(m2, 2), ..., y(mk, k)]
    /// </summary>
    public sealed class LamportOneTimeSignature : ISignatureScheme
    {
        private readonly ICryptographicHash hash;

        private int SubKeySizeInBytes => HashSizeInBits * HashSizeInBytes;

        private int KeySizeInBytes => SubKeySizeInBytes * 2;

        private int HashSizeInBits => hash.SizeInBits;

        private int HashSizeInBytes => hash.SizeInBytes;

        public int SizeInBytes => hash.SizeInBytes;

        public LamportOneTimeSignature(ICryptographicHash hash) => this.hash = hash;

        public (byte[] SecretKey, byte[] PublicKey) GenerateKeys()
        {
            var sk = RandomHelper.GenerateBytes(KeySizeInBytes);
            var pk = new byte[KeySizeInBytes];

            for (var i = 0; i < KeySizeInBytes; i += HashSizeInBytes)
            {
                var yi = sk.AsSpan(i, HashSizeInBytes);
                var zi = pk.AsSpan(i, HashSizeInBytes);

                hash.Compute(yi, zi);
            }

            return (sk, pk);
        }

        public byte[] Sign(byte[] data, byte[] secretKey)
        {
            SplitKey(secretKey, out var sk0, out var sk1);
            Span<byte> m = stackalloc byte[HashSizeInBytes];
            hash.Compute(data, 0, data.Length, m);
            var signature = new byte[KeySizeInBytes];

            for (var i = 0; i < HashSizeInBits; i++)
            {
                var yi = ChunkAt(sk0, sk1, m, i);
                var si = signature.AsSpan(i * HashSizeInBytes, HashSizeInBytes);

                yi.CopyTo(si);
            }

            return signature;
        }

        public bool Verify(byte[] data, byte[] publicKey, byte[] signature)
        {
            SplitKey(publicKey, out var pk0, out var pk1);
            Span<byte> m = stackalloc byte[HashSizeInBytes];
            hash.Compute(data, 0, data.Length, m);
            Span<byte> hi = stackalloc byte[HashSizeInBytes];

            for (var i = 0; i < HashSizeInBits; i++)
            {
                var si = signature.AsSpan(i * HashSizeInBytes, HashSizeInBytes);
                hash.Compute(si, hi);
                var zi = ChunkAt(pk0, pk1, m, i);

                if (!zi.SequenceEqual(hi))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
