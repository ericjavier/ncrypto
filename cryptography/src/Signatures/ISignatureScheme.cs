using System;
using System.Collections.Generic;
using System.Text;

namespace NCrypto.Cryptography.Signatures
{
    public interface ISignatureScheme
    {
        (byte[] SecretKey, byte[] PublicKey) GenerateKeys();

        byte[] Sign(byte[] data, byte[] secretKey);

        bool Verify(byte[] data, byte[] publicKey, byte[] signature);
    }
}
