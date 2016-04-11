using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptopals
{
    class AES
    {
        private static int NumberOfCycles(int keySizeInBytes)
        {
            if (keySizeInBytes == 16)
                return 10;
            else if (keySizeInBytes == 24)
                return 12;
            else
                return 14;
        }

        private static int NumberOfCycles(byte[] key)
        {
            return NumberOfCycles(key.Length);
        }

        //public static byte[] Encrypt(byte[] input, byte[] key)
        //{
        //    int numberOfCycles = NumberOfCycles(key);


        //}
    }
}
