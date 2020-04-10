using System;

namespace NCrypto.Cryptography.Hashes
{
    public interface ICryptographicHash
    {
        int SizeInBytes { get; }

        int SizeInBits => SizeInBytes * 8;

        bool Compute(ReadOnlySpan<byte> data, Span<byte> result);
    }
}
