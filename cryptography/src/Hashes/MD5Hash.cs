using System;
using System.Security.Cryptography;

namespace NCrypto.Cryptography.Hashes
{
    public sealed class MD5Hash : ICryptographicHash
    {
        private readonly MD5 md5 = MD5.Create();

        public int SizeInBytes => 16;

        public bool Compute(ReadOnlySpan<byte> data, Span<byte> result)
        {
            return md5.TryComputeHash(data, result, out var bytesWritten) && bytesWritten == SizeInBytes;
        }
    }
}
