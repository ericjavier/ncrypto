using System;
using System.Collections.Generic;
using System.Text;

namespace NCrypto.Common
{
    public static class MemoryHelper
    {
        public static bool SameContent(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a == b)
            {
                return true;
            }

            if (a.Length != b.Length)
            {
                return false;
            }

            for (var i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
