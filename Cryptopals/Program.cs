using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptopals
{
    class Program
    {
        static void Main(string[] args)
        {
            //2
            //Console.WriteLine(Set1.FixedXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));

            //3
            //Console.WriteLine(Set1.SingleByteXORCipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").clearText);

            //4
            //Console.WriteLine(Set1.DetectSingleCharacterXOR(File.ReadAllLines("input.txt")).clearText);

            //5
            //string originalString = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
            //string key = "ICE";
            //string firstXOR = Set1.RepeatingKeyXOR(originalString, key);

            //Console.WriteLine(firstXOR);
            //Console.WriteLine();

            //string secondXOR = Set1.RepeatingKeyXOR(Set1.HexStringToByteArray(firstXOR), key);

            //Console.WriteLine();
            //Console.WriteLine(secondXOR);

            //Console.WriteLine();
            //Console.WriteLine(Set1.RepeatingKeyXOR(secondXOR, key));

            //Console.WriteLine();
            //Console.WriteLine(ASCIIEncoding.ASCII.GetString(Set1.HexStringToByteArray(secondXOR)));
            //Console.WriteLine();

            //6
            //Console.WriteLine(Utils.HammingDistance("this is a test", "wokka wokka!!!"));
            //Console.WriteLine(Set1.Vigenere(File.ReadAllText("input.txt").Replace("\n", "")).clearText);

            //7
            //string text = File.ReadAllText("input.txt").Replace("\n", "");

            //Console.WriteLine(Set1.AesDecrypt(Convert.FromBase64String(text), ASCIIEncoding.ASCII.GetBytes("YELLOW SUBMARINE")));

            //Console.ReadKey();

        }
    }
}
