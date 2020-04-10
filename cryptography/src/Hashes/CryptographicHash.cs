using System;

namespace NCrypto.Cryptography.Hashes
{
    public static class CryptographicHash
    {
        public static bool Compute(this ICryptographicHash hash, byte[] data, int dataOffset, int dataCount, byte[] result, int resultOffset)
        {
            if (dataOffset < 0 || dataOffset + dataCount > data.Length)
            {
                throw new ArgumentException("Offset and count combination is out of the valid range for array.", nameof(dataOffset));
            }

            if (resultOffset + hash.Size > result.Length)
            {
                throw new ArgumentException("Array to small for current hash size.", nameof(result));
            }

            return hash.Compute(data.AsSpan(dataOffset, dataCount), result.AsSpan(resultOffset));
        }

        public static byte[] Compute(this ICryptographicHash hash, byte[] data, int dataOffset, int dataCount)
        {
            var result = new byte[hash.Size];
            if (hash.Compute(data, dataOffset, dataCount, result, 0))
            {
                return result;
            }

            return null;
        }
    }
}
