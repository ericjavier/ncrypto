using System;

namespace NCrypto.Cryptography.Signatures.HashBased
{
    public static class LamportHelper
    {
        public static void SplitKey(Span<byte> key, out Span<byte> subKey0, out Span<byte> subKey1)
        {
            var m = key.Length / 2;

            subKey0 = key.Slice(0, m);
            subKey1 = key.Slice(m, m);
        }

        public static Span<byte> ChunkAt(Span<byte> subKey0, Span<byte> subKey1, Span<byte> mask, int i)
        {
            var m = mask.Length;
            var j = Math.DivRem(i, 8, out var r);
            var subKey = (mask[j] & (1 << r)) == 0 ? subKey0 : subKey1;

            return subKey.Slice(i * m, m);
        }
    }
}
