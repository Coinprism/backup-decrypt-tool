using System;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Coinprism.BackupDecryptTool
{
    public class CoinprismDecryptor
    {
        private readonly static int AesBlockSizeInBytes = 4 * 4;
        private readonly byte[] aesKey;

        public CoinprismDecryptor(int iterations, string password, byte[] salt)
        {
            this.aesKey = StretchPassword(iterations, password, salt);
        }

        private static byte[] StretchPassword(int iterations, string password, byte[] salt)
        {
            return KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: iterations,
                numBytesRequested: 32);
        }

        public byte[] Decrypt(byte[] value)
        {
            BufferedBlockCipher aes = new BufferedBlockCipher(new OfbBlockCipher(new AesEngine(), AesBlockSizeInBytes * 8));
            ArraySegment<byte> iv = new ArraySegment<byte>(value, 0, AesBlockSizeInBytes);
            ArraySegment<byte> secret = new ArraySegment<byte>(value, AesBlockSizeInBytes, value.Length - AesBlockSizeInBytes);

            ParametersWithIV ivAndKey = new ParametersWithIV(new KeyParameter(aesKey), iv.ToArray());
            aes.Init(false, ivAndKey);

            int maximumSize = aes.GetOutputSize(secret.Count);
            byte[] outputBuffer = new byte[maximumSize];
            int length1 = aes.ProcessBytes(secret.ToArray(), 0, secret.Count, outputBuffer, 0);
            int length2 = aes.DoFinal(outputBuffer, length1);

            return new ArraySegment<byte>(outputBuffer, 0, length1 + length2).ToArray();
        }
    }
}
