using NCrypto.Common;
using NCrypto.Cryptography.Hashes;
using System;

using static NCrypto.Cryptography.Signatures.HashBased.LamportHelper;

namespace NCrypto.Cryptography.Signatures.HashBased
{
    /// <summary>
    /// h: X -> Y (one way only)
    /// y: R -> Y (random)
    /// 1 <= r <= n
    /// ms = [m1, m2, ..., mk] // mi = { 0 | 1 }
    /// sk(r) = [sk0, sk1](r)
    ///       = [y(0, 1), y(0, 2), ..., y(0, k), y(1, 1), y(1, 2), ..., y(1, k)](r)
    /// pk(r) = [pk0, pk1](r)
    ///       = [z(0, 1), z(0, 2), ..., z(0, k), z(1, 1), z(1, 2), ..., z(1, k)](r)
    ///       = [h(y(0, 1)), h(y(0, 2)), ..., h(y(0, k)), h(y(1, 1)), h(y(1, 2)), ..., h(y(1, k))](r)
    /// sg = [s1, s2, ..., sk, r]
    ///    = [y(m1, 1)(r), y(m2, 2)(r), ..., y(mk, k)(r), r]
    /// </summary>
    public sealed class LamportNTimesSignature : ISignatureScheme
    {
        private readonly ICryptographicHash hash;
        private readonly byte n;
        private byte r;

        private int SubKeySizeInBytes => HashSizeInBits * HashSizeInBytes;

        private int KeySizeInBytes => 2 * SubKeySizeInBytes;

        private int ComposedKeySizeInBytes => KeySizeInBytes * n;

        private int HashSizeInBits => hash.SizeInBits;

        private int HashSizeInBytes => hash.SizeInBytes;


        public LamportNTimesSignature(ICryptographicHash hash, byte n) => (this.hash, this.n) = (hash, n);

        public (byte[] SecretKey, byte[] PublicKey) GenerateKeys()
        {
            var sk = RandomHelper.GenerateBytes(ComposedKeySizeInBytes);
            var pk = new byte[ComposedKeySizeInBytes];

            for (var i = 0; i < ComposedKeySizeInBytes; i += HashSizeInBytes)
            {
                var yi = sk.AsSpan(i, HashSizeInBytes);
                var zi = pk.AsSpan(i, HashSizeInBytes);

                hash.Compute(yi, zi);
            }

            return (sk, pk);
        }

        public byte[] Sign(byte[] data, byte[] secretKey)
        {
            SplitKey(secretKey.AsSpan(r * KeySizeInBytes, KeySizeInBytes), out var sk0, out var sk1);
            Span<byte> m = stackalloc byte[HashSizeInBytes];
            hash.Compute(data, 0, data.Length, m);
            var signature = new byte[KeySizeInBytes + 1];

            for (var i = 0; i < HashSizeInBits; i++)
            {
                var yi = ChunkAt(sk0, sk1, m, i);
                var si = signature.AsSpan(i * HashSizeInBytes, HashSizeInBytes);

                yi.CopyTo(si);
            }

            signature[KeySizeInBytes] = r;
            r = Convert.ToByte((r + 1) % n);

            return signature;
        }

        public bool Verify(byte[] data, byte[] publicKey, byte[] signature)
        {
            var r = signature[KeySizeInBytes];
            SplitKey(publicKey.AsSpan(r * KeySizeInBytes, KeySizeInBytes), out var pk0, out var pk1);
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
