using System.Security.Cryptography;

namespace PandatechCrypto
{
    public static class Aes256
    {
        private static readonly string Key = Environment.GetEnvironmentVariable("AES_KEY")!;
        private const int KeySize = 256;
        private const int IvSize = 16;

        public static byte[] Encrypt(string plainText)
        {
            return Encrypt(plainText, Key);
        }

        public static byte[] Encrypt(string plainText, string key)
        {
            using var aesAlg = Aes.Create();
            aesAlg.KeySize = KeySize;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.Key = Convert.FromBase64String(key);
            aesAlg.GenerateIV();

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var swEncrypt = new StreamWriter(csEncrypt);
            swEncrypt.Write(plainText);
            swEncrypt.Flush();
            csEncrypt.FlushFinalBlock();

            var encryptedPasswordByte = msEncrypt.ToArray();

            var result = aesAlg.IV.Concat(encryptedPasswordByte).ToArray();
            return result;
        }

        public static string Decrypt(byte[] cipherText)
        {
            return Decrypt(cipherText, Key);
        }

        public static string Decrypt(byte[] cipherText, string key)
        {
            var iv = cipherText.Take(IvSize).ToArray();
            var encrypted = cipherText.Skip(IvSize).ToArray();

            using var aesAlg = Aes.Create();
            aesAlg.KeySize = KeySize;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.Key = Convert.FromBase64String(key);
            aesAlg.IV = iv;

            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(encrypted);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            return srDecrypt.ReadToEnd();
        }
    }
}