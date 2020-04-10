using System.Linq;
using Xunit;

using NCrypto.Common;
using NCrypto.Cryptography;
using NCrypto.Cryptography.Hashes;
using NCrypto.Cryptography.Signatures;
using System.Collections.Generic;

namespace Cryptography.Test
{
    public class SignaturesTests
    {
        [Theory]
        [MemberData(nameof(SignaturesWithData))]
        public void VerifyValidSignatures(ISignatureScheme scheme, byte[] data)
        {
            var (sk, pk) = scheme.GenerateKeys();
            var signature = scheme.Sign(data, sk);

            Assert.True(scheme.Verify(data, pk, signature));
        }

        [Theory]
        [MemberData(nameof(SignaturesWithData))]
        public void DoNotVerifyForgeries(ISignatureScheme scheme, byte[] data)
        {
            var forgery = new byte[data.Length];
            data.CopyTo(forgery, 0);
            forgery[RandomHelper.Generate(0, data.Length)]++;

            var (sk, pk) = scheme.GenerateKeys();
            var signature = scheme.Sign(data, sk);

            Assert.False(scheme.Verify(forgery, pk, signature));
        }

        public static IEnumerable<object[]> SignaturesWithData()
        {
            var schemes = new List<ISignatureScheme>
            {
                new LamportOneTimeSignature(new SHA256Hash()),
            };

            var data = Enumerable.Range(0, 10).Select(i => RandomHelper.GenerateBytes(1024)).ToList();

            foreach (var scheme in schemes)
            {
                foreach (var d in data)
                {
                    yield return new object[] { scheme, d };
                }
            }
        }
    }
}
