using NCrypto.Cryptography.Hashes;
using NCrypto.Cryptography.Signatures;
using System;

namespace NCrypto.Sandbox
{
    class Program
    {
        static void Main(string[] args)
        {
            var h = new SHA1Hash();
            var m1 = new byte[] { 23, 23, 42, 3, 2, 3, 34, 3, 42, 34, 53, 45, 3, 45, 3, 45, 3, 45, 3, 45, 3, 45, 3, 0, };
            var m2 = new byte[] { 23, 23, 42, 3, 2, 3, 34, 3, 42, 34, 53, 45, 3, 45, 3, 45, 3, 45, 3, 45, 3, 45, 3, 1, };

            var h1 = h.Compute(m1, 0, m1.Length);
            var h2 = h.Compute(m2, 0, m2.Length);

            Console.ReadLine();
        }
    }
}
