using System;
using System.Linq;
using NBitcoin;

namespace Coinprism.BackupDecryptTool
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Coinprism Backup Decryption Tool v1.0");
            Console.WriteLine();

            Console.Write("Encrypted value to decrypt: ");
            string data = Console.ReadLine();

            Console.Write("Salt: ");
            string salt = Console.ReadLine();

            Console.Write("Password: ");
            string password = Console.ReadLine();

            CoinprismDecryptor decryptor = new CoinprismDecryptor(2000, password, BinaryData.Parse(salt).Value.ToArray());

            byte[] encryptedData = BinaryData.Parse(data).Value.ToArray();
            if (encryptedData.Length < 16)
            {
                Console.WriteLine("Error: The decrypted data must be at least 128 bits.");
                return;
            }

            byte[] result = decryptor.Decrypt(encryptedData);

            BitcoinSecret secret = new BitcoinSecret(new Key(result), Network.Main);
            BitcoinPubKeyAddress address = secret.PubKey.GetAddress(Network.Main);

            Console.WriteLine();
            Console.WriteLine($"Private key:  {secret.ToString()}");
            Console.WriteLine($"Address:      {address.ToString()}");
        }
    }
}
