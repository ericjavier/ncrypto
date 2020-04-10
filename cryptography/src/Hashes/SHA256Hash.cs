using System;
using System.Security.Cryptography;

namespace NCrypto.Cryptography.Hashes
{
    public sealed class SHA256Hash : ICryptographicHash
    {
        private readonly SHA256 sha256 = SHA256.Create();

        public int SizeInBytes => 32;

        public bool Compute(ReadOnlySpan<byte> data, Span<byte> result)
        {
            return sha256.TryComputeHash(data, result, out int bytesWritten) && bytesWritten == SizeInBytes;
        }
    }
}
