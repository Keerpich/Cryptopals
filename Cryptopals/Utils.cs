using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptopals
{
    class Utils
    {
        static Dictionary<char, int> frequencyDict = new Dictionary<char, int>()
        {
            { 'e', 27 },
            { 't', 26 },
            { 'a', 25 },
            { 'o', 24 },
            { 'i', 23 },
            { 'n', 22 },
            { 's', 21 },
            { 'r', 20 },
            { 'h', 19 },
            { 'l', 18 },
            { 'd', 17 },
            { 'c', 16 },
            { 'u', 15 },
            { 'm', 14 },
            { 'f', 13 },
            { 'p', 12 },
            { 'g', 11 },
            {'w', 10 },
            { 'y', 9 },
            { 'b', 8 },
            { 'v', 7 },
            { 'k', 6 },
            { 'x', 5 },
            { ' ', 4 },
            { 'j', 3 },
            { 'q', 2 },
            { 'z', 1 }
        };

        public static int TotalFitnessOfString(string text)
        {
            int totalFitness = 0;

            foreach (char c in text)
            {
                if(frequencyDict.ContainsKey(c))
                    totalFitness += frequencyDict[c];
            }

            return totalFitness;
        }


        public static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        public static int HammingDistance(string s1, string s2)
        {
            return HammingDistance(new BitArray(GetBytes(s1)), new BitArray(GetBytes(s2)));
        }


        public static int HammingDistance(BitArray s1, BitArray s2)
        {
            int distance = 0;

            for(int i = 0; i < s1.Length; i++)
            {
                if (s1[i] != s2[i])
                    distance++;
            }

            return distance;
        }

    }
}
