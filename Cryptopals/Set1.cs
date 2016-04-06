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
                int fitness = Utils.TotalFitnessOfString(plainText);

                VigenereDecryptResult vdr = new VigenereDecryptResult();
                vdr.clearText = plainText;
                vdr.key = real_key;
                vdr.fitness = fitness;

                results.Add(vdr);
            }

            results.Sort((v1, v2) => v1.fitness.CompareTo(v2.fitness));
            
            return results[results.Count - 1];
        }

        private static RijndaelManaged GetCryptoAlgorithm()
        {
            RijndaelManaged algorithm = new RijndaelManaged();
            //set the mode, padding and block size
            algorithm.Padding = PaddingMode.PKCS7;
            algorithm.Mode = CipherMode.ECB;
            algorithm.KeySize = 128;
            algorithm.BlockSize = 128;
            return algorithm;
        }


        public static string AesDecrypt(byte[] inputBytes, byte[] key)
        {
            byte[] outputBytes = inputBytes;
            byte[] keyAndIvBytes = key;

            string plaintext = string.Empty;

            using (MemoryStream memoryStream = new MemoryStream(outputBytes))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm().CreateDecryptor(keyAndIvBytes, keyAndIvBytes), CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            return plaintext;
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
            List<byte> unpadded = new List<byte>(Utils.GetBytes(toPad));
            Console.WriteLine(blockLength);
            Console.WriteLine(unpadded.Count);
            int bytesToBeAdded = blockLength - unpadded.Count % blockLength;

            Console.WriteLine(bytesToBeAdded);

            while(unpadded.Count % blockLength != 0)
            {
                unpadded.Add((byte)bytesToBeAdded);
            }

            return Utils.GetString(unpadded.ToArray());
        }
        #endregion

    }
}
