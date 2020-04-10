using System;
using System.Security.Cryptography;

namespace NCrypto.Cryptography.Hashes
{
    public sealed class SHA1Hash : ICryptographicHash
    {
        private readonly SHA1 sha1 = SHA1.Create();

        public int Size => 20;

        public bool Compute(ReadOnlySpan<byte> data, Span<byte> result)
        {
            return sha1.TryComputeHash(data, result, out var bytesWritten) && bytesWritten == Size;
        }
    }
}
