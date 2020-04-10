using NCrypto.Common;
using NCrypto.Cryptography.Hashes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics.Contracts;

namespace NCrypto.Cryptography.Signatures
{
    public sealed class LamportOneTimeSignature : ISignatureScheme
    {
        private readonly ICryptographicHash hash;

        public LamportOneTimeSignature(ICryptographicHash hash)
        {
            this.hash = hash;
        }

        public (byte[] SecretKey, byte[] PublicKey) GenerateKeys()
        {
            var sk = Enumerable.Range(0, 512).Select(it => RandomHelper.GenerateBytes(32)).ToList();
            var pk = sk.Select(it => hash.Compute(it, 0, it.Length)).ToList();

            return (sk.SelectMany(it => it).ToArray(), pk.SelectMany(it => it).ToArray());
        }

        public byte[] Sign(byte[] data, byte[] privateKey)
        {
            var m = hash.Compute(data, 0, data.Length);
            var sk0 = privateKey.AsSpan(0, 8192);
            var sk1 = privateKey.AsSpan(8192, 8192);
            var signature = new List<byte>(16384);

            for (int i = 0; i < 256; i++)
            {
                var j = Math.DivRem(i, 8, out var r);
                var sk = (m[j] & (1 << r)) == 0 ? sk0 : sk1;
                signature.AddRange(sk.Slice(i * 32, 32).ToArray());
            }

            return signature.ToArray();
        }

        public bool Verify(byte[] data, byte[] publicKey, byte[] signature)
        {
            var m = hash.Compute(data, 0, data.Length);
            var pk0 = publicKey.AsSpan(0, 8192);
            var pk1 = publicKey.AsSpan(8192, 8192);
            var h = new Span<byte>(new byte[32]);

            for (int i = 0; i < 256; i++)
            {
                var j = Math.DivRem(i, 8, out var r);
                var pk = (m[j] & (1 << r)) == 0 ? pk0 : pk1;
                var s = signature.AsSpan(i * 32, 32);
                hash.Compute(s, h);
                var p = pk.Slice(i * 32, 32);

                for (int k = 0; k < 32; k++)
                {
                    if (h[k] != p[k])
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }
}
