using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptopals
{
    class Set1
    {

        #region BaseConversion
        public static string HexToB64(string hex)
        {
            return Convert.ToBase64String(HexStringToByteArray(hex));
        }

        public static string B64ToString(string b64)
        {
            return HexByteArrayToString(Convert.FromBase64String(b64));
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string HexByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static string ByteArrayToASCIIString(byte[] ba)
        {
            return Encoding.ASCII.GetString(ba);
        }

        #endregion

        #region XOROperations
        public static string FixedXOR(string hex1, string hex2)
        {
            byte[] op1 = HexStringToByteArray(hex1), op2 = HexStringToByteArray(hex2);
            byte[] result = new byte[op1.Length];

            for (int i = 0; i < op1.Length; i++)
            {
                result[i] = (byte)(op1[i] ^ op2[i]);

            }

            return HexByteArrayToString(result);
        }

        public static string SingleByteFullHex(string cipher, byte key)
        {
            byte[] hexByte = HexStringToByteArray(cipher);

            byte[] result = new byte[hexByte.Length];

            for(int i = 0; i < hexByte.Length; i++)
            {
                result[i] = (byte)(hexByte[i] ^ key);
            }

            return HexByteArrayToString(result);
        }

        public static string RepeatingKeyXOR(string cipher, string key)
        {
            byte[] cipherBytes = ASCIIEncoding.ASCII.GetBytes(cipher);
            byte[] keyBytes = ASCIIEncoding.ASCII.GetBytes(key);

            byte[] result = new byte[cipherBytes.Length];

            for (int i = 0; i < cipherBytes.Length; i++)
            {
                result[i] = (byte)(cipherBytes[i] ^ keyBytes[i % keyBytes.Length]);
            }

            return HexByteArrayToString(result);
        }
        #endregion

        #region Structs
        public struct SingleByteDecryptResult
        {
            public int key;
            public int fitness;
            public string clearText;
        }
        #endregion

        #region Ciphers
        public static SingleByteDecryptResult SingleByteXORCipher(string hex)
        {
            List<SingleByteDecryptResult> results = new List<SingleByteDecryptResult>();

            for (int k = 0; k < 256; k++)
            {
                string clearText = ByteArrayToASCIIString(HexStringToByteArray(SingleByteFullHex(hex, Convert.ToByte(k))));
                int value = Utils.TotalFitnessOfString(clearText);

                SingleByteDecryptResult sbdr = new SingleByteDecryptResult();
                sbdr.key = k;
                sbdr.fitness = value;
                sbdr.clearText = clearText;

                results.Add(sbdr);
            }

            results.Sort((r1, r2) => r1.fitness.CompareTo(r2.fitness));

            return results[results.Count - 1];
        }

        public static SingleByteDecryptResult DetectSingleCharacterXOR(string[] allHexs)
        {
            List<SingleByteDecryptResult> bestResults = new List<SingleByteDecryptResult>();

            foreach(string hex in allHexs)
            {
                bestResults.Add(SingleByteXORCipher(hex));
            }

            bestResults.Sort((r1, r2) => r1.fitness.CompareTo(r2.fitness));

            return bestResults[bestResults.Count - 1];
        }

        public static string Vigenere(string base4CipheredText)
        {
            string cipheredText = B64ToString(base4CipheredText);
            byte[] cipheredBytes = Utils.GetBytes(cipheredText);

            int bestKeysize = -1;
            float minDistance = -1f;

            for (int keysize = 2; keysize < (40 < cipheredText.Length / 2 ? 40 : cipheredText.Length / 2); keysize++)
            {
                byte[] chunk1 = new byte[keysize];
                byte[] chunk2 = new byte[keysize];

                for (int i = 0; i < keysize; i++)
                    chunk1[i] = cipheredBytes[i];
                for (int i = keysize; i < 2 * keysize; i++)
                    chunk2[i - keysize] = cipheredBytes[i];

                float distance = Utils.HammingDistance(new BitArray(chunk1), new BitArray(chunk2)) / keysize;

                if(distance < minDistance || minDistance == -1)
                {
                    minDistance = distance;
                    bestKeysize = keysize;
                }
            }

            //now we probably know the keysize
            //and we break the text into chunk of bestKeysize length

            List<byte[]> allChunks = new List<byte[]>();

            for (int i = 0; i < cipheredBytes.Length; i+=bestKeysize)
            {
                int chunkLength = cipheredBytes.Length - i < bestKeysize ? cipheredBytes.Length - 1 : bestKeysize;
                allChunks.Add(new byte[chunkLength]);

                for (int j = 0; j < chunkLength; j++)
                {
                    allChunks[i][j] = cipheredBytes[i + j];
                }
            }

            //make new blocks according to step 6

            List<byte[]> allBlocks = new List<byte[]>();

            throw new NotImplementedException();

        }
        #endregion

    }
}
