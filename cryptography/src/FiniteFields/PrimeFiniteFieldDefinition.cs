using System;
using System.Collections.Generic;
using System.Text;

namespace NCrypto.Cryptography.FiniteFields
{
    public sealed class PrimeFiniteFieldDefinition : IFiniteFieldDefinition<int>
    {
        private readonly int p;

        public PrimeFiniteFieldDefinition(int p) => this.p = p;

        public int AdditiveIdentity => 0;

        public int MultiplicativeIdentity => 1;

        public int Add(int x, int y) => (x + y) % p;

        public int AdditiveInverse(int x) => (-x) % p;

        public bool Equals(int x, int y)
        {
            throw new NotImplementedException();
        }

        public int Multiply(int x, int y) => (x * y) % p;

        public int MultiplicativeInverse(int x)
        {
            throw new NotImplementedException();
        }
    }
}
