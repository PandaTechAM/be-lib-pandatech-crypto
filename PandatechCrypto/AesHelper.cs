using System.Security.Cryptography;

namespace PandatechCrypto
{
    public static class AesHelper
    {

        private static readonly string Key = Environment.GetEnvironmentVariable("AES_KEY")!;

        public static byte[] Encrypt(string plainText)
        {

            using var aesAlg = Aes.Create();
            aesAlg.KeySize = 256;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.Key = Convert.FromBase64String(Key);
            aesAlg.GenerateIV();

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var swEncrypt = new StreamWriter(csEncrypt);
            swEncrypt.Write(plainText);
            swEncrypt.Flush();
            csEncrypt.FlushFinalBlock();

            var encryptedPasswordByte = msEncrypt.ToArray();

            byte[] result = aesAlg.IV.Concat(encryptedPasswordByte).ToArray();
            return result;
        }

        public static string Decrypt(byte[] cipherText)
        {
            int splitIndex = 16;

            byte[] iv = cipherText.Take(splitIndex).ToArray();
            byte[] encrypted = cipherText.Skip(splitIndex).ToArray();

            using var aesAlg = Aes.Create();
            aesAlg.KeySize = 256;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.Key = Convert.FromBase64String(Key);
            aesAlg.IV = iv;

            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(encrypted);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            return srDecrypt.ReadToEnd();
        }
    }
}