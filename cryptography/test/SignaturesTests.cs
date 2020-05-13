using System.Linq;
using Xunit;

using NCrypto.Common;
using NCrypto.Cryptography;
using NCrypto.Cryptography.Hashes;
using NCrypto.Cryptography.Signatures;
using System.Collections.Generic;
using System;
using NCrypto.Cryptography.Signatures.HashBased;

namespace Cryptography.Test
{
    public class SignaturesTests
    {
        [Theory]
        [MemberData(nameof(SignaturesWithData))]
        public void VerifyValidSignatures<T>(Func<T> scheme, byte[] data) where T : ISignatureScheme
        {
            var (sk, pk) = scheme().GenerateKeys();
            var signature = scheme().Sign(data, sk);

            Assert.True(scheme().Verify(data, pk, signature));
        }

        [Theory]
        [MemberData(nameof(SignaturesWithData))]
        public void DoNotVerifyForgeries<T>(Func<T> scheme, byte[] data) where T : ISignatureScheme
        {
            var forgery = new byte[data.Length];
            data.CopyTo(forgery, 0);
            forgery[RandomHelper.Generate(0, data.Length)]++;

            var (sk, pk) = scheme().GenerateKeys();
            var signature = scheme().Sign(data, sk);

            Assert.False(scheme().Verify(forgery, pk, signature));
        }

        public static IEnumerable<object[]> SignaturesWithData()
        {
            var schemes = new List<Func<ISignatureScheme>>
            {
                () => new LamportOneTimeSignature(new SHA256Hash()),
                () => new LamportOneTimeSignature(new MD5Hash()),
                () => new LamportOneTimeSignature(new SHA1Hash()),
                () => new LamportNTimesSignature(new SHA256Hash(), 5),
                () => new LamportNTimesSignature(new MD5Hash(), 6),
                () => new LamportNTimesSignature(new SHA1Hash(), 7),
            };

            static IEnumerable<byte[]> Data(int length) => Enumerable.Range(0, 10).Select(i => RandomHelper.GenerateBytes(length));
            var data = Data(1024).Concat(Data(208)).ToList();

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
