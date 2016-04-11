using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

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

        public static string RepeatingKeyXOR(byte[] cipher, byte[] key)
        {
            byte[] cipherBytes = cipher;
            byte[] keyBytes = key;

            byte[] result = new byte[cipherBytes.Length];

            for (int i = 0; i < cipherBytes.Length; i++)
            {
                result[i] = (byte)(cipherBytes[i] ^ keyBytes[i % keyBytes.Length]);
            }

            return HexByteArrayToString(result);
        }

        public static string RepeatingKeyXOR(byte[] cipher, string key)
        {
            byte[] cipherBytes = cipher;
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

        public struct VigenereDecryptResult
        {
            public string key;
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
                int value = TotalFitnessOfString(clearText);

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

        public static VigenereDecryptResult Vigenere(string base64CipheredText)
        {
            string cipheredText = B64ToString(base64CipheredText);
            byte[] cipheredBytes = HexStringToByteArray(cipheredText);

            List<VigenereDecryptResult> results = new List<VigenereDecryptResult>();
            
            for (int bestKeysize = 2; bestKeysize < 41; bestKeysize++)
            {
                List<byte[]> allChunks = new List<byte[]>();

                for (int i = 0; i < cipheredBytes.Length; i += bestKeysize)
                {
                    int chunkLength = cipheredBytes.Length - i < bestKeysize ? cipheredBytes.Length - i : bestKeysize;
                    allChunks.Add(new byte[chunkLength]);

                    for (int j = 0; j < chunkLength; j++)
                    {
                        allChunks[i / bestKeysize][j] = cipheredBytes[i + j];
                    }
                }

                //make new blocks according to step 6

                int minChunkLength = -1;
                foreach (byte[] chunk in allChunks)
                {
                    if (chunk.Length < minChunkLength || minChunkLength == -1)
                        minChunkLength = chunk.Length;
                }

                List<List<byte>> allBlocks = new List<List<byte>>();

                for (int i = 0; i < bestKeysize; i++)
                {
                    allBlocks.Add(new List<byte>());

                    foreach (byte[] chunk in allChunks)
                    {
                        if (chunk.Length > i)
                            allBlocks[i].Add(chunk[i]);
                    }
                }

                string real_key = "";

                foreach (List<byte> block in allBlocks)
                {
                    real_key += (char)SingleByteXORCipher(HexByteArrayToString(block.ToArray())).key;
                }

                string plainText = ASCIIEncoding.ASCII.GetString(HexStringToByteArray(RepeatingKeyXOR(cipheredBytes, real_key)));
                int fitness = TotalFitnessOfString(plainText);

                VigenereDecryptResult vdr = new VigenereDecryptResult();
                vdr.clearText = plainText;
                vdr.key = real_key;
                vdr.fitness = fitness;

                results.Add(vdr);
            }

            results.Sort((v1, v2) => v1.fitness.CompareTo(v2.fitness));
            
            return results[results.Count - 1];
        }
        #endregion

        #region AES
        private static RijndaelManaged GetCryptoAlgorithm(CipherMode cm)
        {
            RijndaelManaged algorithm = new RijndaelManaged();
            //set the mode, padding and block size
            algorithm.Padding = PaddingMode.PKCS7;
            algorithm.Mode = cm;
            algorithm.KeySize = 128;
            algorithm.BlockSize = 128;
            return algorithm;
        }


        public static byte[] AesDecryptECB(byte[] inputBytes, byte[] key)
        {
            byte[] outputBytes = inputBytes;
            byte[] keyAndIvBytes = key;


            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm(CipherMode.ECB).CreateDecryptor(keyAndIvBytes, keyAndIvBytes), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                }

                return memoryStream.ToArray();
            }

        }

        public static byte[] AesEncryptECB(byte[] inputBytes, byte[] key)
        {
            byte[] outputBytes = inputBytes;
            byte[] keyAndIvBytes = key;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm(CipherMode.ECB).CreateEncryptor(keyAndIvBytes, keyAndIvBytes), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                }

                return memoryStream.ToArray();
            }

        }

        public static byte[] AesDecryptCBC(byte[] inputBytes, byte[] key, byte[] iv)
        {
            byte[] outputBytes = inputBytes;
            byte[] keyBytes = key;
            byte[] ivBytes = iv;


            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm(CipherMode.CBC).CreateDecryptor(keyBytes, ivBytes), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                }

                return memoryStream.ToArray();
            }

        }


        public static byte[] AesEncryptCBC(byte[] inputBytes, byte[] key, byte[] iv)
        {
            byte[] outputBytes = inputBytes;
            byte[] keyBytes = key;
            byte[] ivBytes = iv;


            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm(CipherMode.CBC).CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                }

                return memoryStream.ToArray();
            }

        }

        public static string[] DetectECB(string[] input)
        {
            List<string> result = new List<string>();

            foreach (string vline in input)
            {
                string line = vline.Trim();
                byte[] lineBytes = Set1.HexStringToByteArray(line);

                List<byte[]> chunksOf16 = new List<byte[]>();

                for (int i = 0; i < lineBytes.Length; i += 16)
                {
                    byte[] chunk = new byte[16];

                    for (int j = 0; j < 16; j++)
                        chunk[j] = lineBytes[i + j];

                    chunksOf16.Add(chunk);
                }

                for (int x = 0; x < chunksOf16.Count; x++)
                {
                    for (int y = 0; y < chunksOf16.Count; y++)
                    {
                        if (x == y) continue;

                        bool areEqual = true;

                        for (int k = 0; k < 16; k++)
                        {
                            if (chunksOf16[x][k] != chunksOf16[y][k])
                                areEqual = false;
                        }

                        if (areEqual && !result.Contains(line))
                        {
                            result.Add(line);
                        }
                    }
                }

            }

            return result.ToArray();
        }

        public static string Pkcs7Padding(string toPad, int blockLength = 16)
        {
            List<byte> unpadded = new List<byte>(GetBytes(toPad));
            Console.WriteLine(blockLength);
            Console.WriteLine(unpadded.Count);
            int bytesToBeAdded = blockLength - unpadded.Count % blockLength;

            Console.WriteLine(bytesToBeAdded);

            while (unpadded.Count % blockLength != 0)
            {
                unpadded.Add((byte)bytesToBeAdded);
            }

            return GetString(unpadded.ToArray());
        }

        public static byte[] JitteryAESEncryption(byte[] input)
        {
            return RandomEncrypter(AppendRandomBytes(input));
        }

        private static string RandomAESKey()
        {
            Random rnd = new Random();

            int keysize = 16;
            String key = "";


            for (int i = 0; i < keysize; i++)
            {
                key += (char)rnd.Next(256);
            }

            return key;
        }

        private static byte[] RandomEncrypter(byte[] plaintext)
        {
            Random rnd = new Random();

            int type = rnd.Next(2);
            
            return (type == 0) ? (AesEncryptECB(plaintext, GetBytes(RandomAESKey()))) : 
                (AesEncryptCBC(plaintext, GetBytes(RandomAESKey()), GetBytes(RandomAESKey())));
        }

        public static bool IsItAESECB(byte[] input)
        {
            byte[] lineBytes = input;

            List<byte[]> chunksOf16 = new List<byte[]>();

            for (int i = 0; i < lineBytes.Length; i += 16)
            {
                byte[] chunk = new byte[16];

                for (int j = 0; j < 16; j++)
                    chunk[j] = lineBytes[i + j];

                chunksOf16.Add(chunk);
            }

            for (int x = 0; x < chunksOf16.Count; x++)
            {
                for (int y = 0; y < chunksOf16.Count; y++)
                {
                    if (x == y) continue;

                    bool areEqual = true;

                    for (int k = 0; k < 16; k++)
                    {
                        if (chunksOf16[x][k] != chunksOf16[y][k])
                            areEqual = false;
                    }

                    if (areEqual)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        
        #endregion

        #region Utils
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
                if (frequencyDict.ContainsKey(c))
                    totalFitness += frequencyDict[c];
            }

            return totalFitness;
        }


        public static byte[] GetBytes(string str)
        {
            return Encoding.ASCII.GetBytes(str);
        }

        public static string GetString(byte[] bytes)
        {
            return Encoding.ASCII.GetString(bytes);
        }

        public static int HammingDistance(string s1, string s2)
        {
            return HammingDistance(new BitArray(GetBytes(s1)), new BitArray(GetBytes(s2)));
        }


        public static int HammingDistance(BitArray s1, BitArray s2)
        {
            int distance = 0;

            for (int i = 0; i < s1.Length; i++)
            {
                if (s1[i] != s2[i])
                    distance++;
            }

            return distance;
        }

        public static byte[] AppendRandomBytes(byte[] original)
        {
            Random rnd = new Random();

            int before = rnd.Next(5, 11);
            int after = rnd.Next(5, 11);

            byte[] prefix = new byte[before];
            byte[] suffix = new byte[after];

            for (int i = 0; i < before; i++)
            {
                int value = rnd.Next(256);
                prefix[i] = (byte)value;
            }

            for (int i = 0; i < after; i++)
            {
                int value = rnd.Next(256);
                suffix[i] = (byte)value;
            }

            byte[] result = new byte[original.Length + before + after];

            for (int i = 0; i < before; i++)
            {
                result[i] = prefix[i];
            }

            for (int i = 0; i < original.Length; i++)
            {
                result[i + before] = original[i];
            }
            for (int i = 0; i < after; i++)
            {
                result[i + before + original.Length] = suffix[i];
            }

            return result;
        }
        #endregion

    }
}
