using System;

namespace NCrypto.Cryptography.Hashes
{
    public interface ICryptographicHash
    {
        int Size { get; }

        bool Compute(ReadOnlySpan<byte> data, Span<byte> result);
    }
}
