using System;

namespace NCrypto.Common
{
    public static class RandomHelper
    {
        public static int Generate(int inclusiveMinValue, int exclusiveMaxValue)
        {
            var random = new Random();
            return random.Next(inclusiveMinValue, exclusiveMaxValue);
        }

        public static byte[] GenerateBytes(int length)
        {
            var random = new Random();
            var buffer = new byte[length];
            random.NextBytes(buffer);

            return buffer;
        }
    }
}
