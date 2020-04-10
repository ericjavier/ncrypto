using NCrypto.Common;
using NCrypto.Cryptography.Hashes;
using System;

namespace NCrypto.Cryptography.Signatures
{
    public sealed class LamportOneTimeSignature : ISignatureScheme
    {
        private readonly ICryptographicHash hash;
        private readonly int subKeySizeInBytes; 
        private readonly int keySizeInBytes;
        private readonly int hashSizeInBits;
        private readonly int hashSizeInBytes;

        public LamportOneTimeSignature(ICryptographicHash hash)
        {
            this.hash = hash;

            hashSizeInBits = hash.SizeInBits;
            hashSizeInBytes = hash.SizeInBytes;
            subKeySizeInBytes = hashSizeInBits* hashSizeInBytes;
            keySizeInBytes = subKeySizeInBytes * 2;
        }

        public (byte[] SecretKey, byte[] PublicKey) GenerateKeys()
        {
            var sk = RandomHelper.GenerateBytes(keySizeInBytes);
            var pk = new byte[keySizeInBytes];

            for (var i = 0; i < keySizeInBytes; i += hashSizeInBytes)
            {
                hash.Compute(sk, i, hashSizeInBytes, pk, i);
            }

            return (sk, pk);
        }

        public byte[] Sign(byte[] data, byte[] privateKey)
        {
            var m = hash.Compute(data, 0, data.Length);
            var sk0 = privateKey.AsSpan(0, subKeySizeInBytes);
            var sk1 = privateKey.AsSpan(subKeySizeInBytes, subKeySizeInBytes);
            var signature = new byte[keySizeInBytes];

            for (var i = 0; i < hashSizeInBits; i++)
            {
                var j = Math.DivRem(i, 8, out var r);
                var sk = (m[j] & (1 << r)) == 0 ? sk0 : sk1;

                sk.Slice(i * hashSizeInBytes, hashSizeInBytes).CopyTo(signature.AsSpan(i * hashSizeInBytes));
            }

            return signature;
        }

        public bool Verify(byte[] data, byte[] publicKey, byte[] signature)
        {
            var m = hash.Compute(data, 0, data.Length);
            var pk0 = publicKey.AsSpan(0, subKeySizeInBytes);
            var pk1 = publicKey.AsSpan(subKeySizeInBytes, subKeySizeInBytes);
            Span<byte> h = stackalloc byte[hashSizeInBytes];

            for (var i = 0; i < hashSizeInBits; i++)
            {
                var j = Math.DivRem(i, 8, out var r);
                var pk = (m[j] & (1 << r)) == 0 ? pk0 : pk1;

                hash.Compute(signature.AsSpan(i * hashSizeInBytes, hashSizeInBytes), h);
                if (!MemoryHelper.SameContent(h, pk.Slice(i * hashSizeInBytes, hashSizeInBytes)))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
