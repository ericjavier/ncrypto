using System;
using System.Collections.Generic;
using System.Text;

namespace NCrypto.Cryptography.FiniteFields
{
    public interface IFiniteFieldDefinition<T> where T : notnull
    {
        T AdditiveIdentity { get; }

        T MultiplicativeIdentity { get; }

        T Add(T x, T y);

        T Multiply(T x, T y);

        T AdditiveInverse(T x);

        T MultiplicativeInverse(T x);

        bool Equals(T x, T y);

        bool AreAdditiveInverses(T x, T y) => Equals(Add(x, y), AdditiveIdentity);

        bool AreMultiplicativeInverses(T x, T y) => Equals(Multiply(x, y), MultiplicativeIdentity);

    }
}
