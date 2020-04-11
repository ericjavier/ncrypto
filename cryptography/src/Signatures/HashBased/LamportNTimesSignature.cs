using NCrypto.Common;
using NCrypto.Cryptography.Hashes;
using System;

namespace NCrypto.Cryptography.Signatures
{
    public sealed class LamportNTimesSignature : ISignatureScheme
    {
        private readonly ICryptographicHash hash;
        private readonly byte n;
        private readonly int subKeySizeInBytes; 
        private readonly int keySizeInBytes;
        private readonly int composedKeySizeInBytes;
        private readonly int hashSizeInBits;
        private readonly int hashSizeInBytes;

        private byte k;

        public LamportNTimesSignature(ICryptographicHash hash, byte n)
        {
            this.hash = hash;
            this.n = n;

            hashSizeInBits = hash.SizeInBits;
            hashSizeInBytes = hash.SizeInBytes;
            subKeySizeInBytes = hashSizeInBits* hashSizeInBytes;
            keySizeInBytes = subKeySizeInBytes * 2;
            composedKeySizeInBytes = keySizeInBytes * n;
        }

        public (byte[] SecretKey, byte[] PublicKey) GenerateKeys()
        {
            var sk = RandomHelper.GenerateBytes(composedKeySizeInBytes);
            var pk = new byte[composedKeySizeInBytes];

            for (var i = 0; i < composedKeySizeInBytes; i += hashSizeInBytes)
            {
                hash.Compute(sk, i, hashSizeInBytes, pk, i);
            }

            return (sk, pk);
        }

        public byte[] Sign(byte[] data, byte[] secretKey)
        {
            var kSecretKey = secretKey.AsSpan(k * keySizeInBytes, keySizeInBytes);

            var m = hash.Compute(data, 0, data.Length);
            var sk0 = kSecretKey.Slice(0, subKeySizeInBytes);
            var sk1 = kSecretKey.Slice(subKeySizeInBytes, subKeySizeInBytes);
            var signature = new byte[keySizeInBytes + 1];

            for (var i = 0; i < hashSizeInBits; i++)
            {
                var j = Math.DivRem(i, 8, out var r);
                var sk = (m[j] & (1 << r)) == 0 ? sk0 : sk1;

                sk.Slice(i * hashSizeInBytes, hashSizeInBytes).CopyTo(signature.AsSpan(i * hashSizeInBytes));
            }

            signature[keySizeInBytes] = k;
            k = Convert.ToByte((k + 1) % n);

            return signature;
        }

        public bool Verify(byte[] data, byte[] publicKey, byte[] signature)
        {
            var k = signature[keySizeInBytes];
            var kPublicKey = publicKey.AsSpan(k * keySizeInBytes, keySizeInBytes);

            var m = hash.Compute(data, 0, data.Length);
            var pk0 = kPublicKey.Slice(0, subKeySizeInBytes);
            var pk1 = kPublicKey.Slice(subKeySizeInBytes, subKeySizeInBytes);
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
