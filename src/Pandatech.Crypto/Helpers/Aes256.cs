using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Pandatech.Crypto.Helpers;

[Obsolete(
   "This class is deprecated due to security concerns. Use Aes256Siv instead. For migration purposes we let this obsolete class with AesMigration class to make migration easier. Later this class will be removed.")]
public static class Aes256
{
   private const int KeySize = 256;
   private const int IvSize = 16;
   private const int HashSize = 64;
   private static string? Key { get; set; }

   public static byte[] Encrypt(string plainText)
   {
      return EncryptWithHashInner(plainText);
   }

   public static byte[] EncryptWithoutHash(string plainText)
   {
      return EncryptWithoutHashInner(plainText, null);
   }

   public static byte[] Encrypt(string plainText, string key)
   {
      ValidateKey(key);

      return EncryptWithHashInner(plainText, key);
   }

   public static byte[] EncryptWithoutHash(string plainText, string key)
   {
      ValidateKey(key);

      return EncryptWithoutHashInner(plainText, key);
   }

   public static void Encrypt(Stream inputStream, Stream outputStream, string? key = null)
   {
      key ??= Key;
      ValidateKey(key);
      using var aesAlg = Aes.Create();
      aesAlg.KeySize = KeySize;
      aesAlg.Padding = PaddingMode.PKCS7;
      aesAlg.Key = Convert.FromBase64String(key);
      aesAlg.GenerateIV();

      outputStream.Write(aesAlg.IV, 0, aesAlg.IV.Length);

      using var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
      using var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write, true);
      inputStream.CopyTo(cryptoStream);
   }

   private static byte[] EncryptWithHashInner(string plainText, string? key = null)
   {
      key ??= Key;
      var encryptedBytes = EncryptWithoutHashInner(plainText, key);
      var hashBytes = Sha3.Hash(plainText);
      return hashBytes.Concat(encryptedBytes)
                      .ToArray();
   }

   private static byte[] EncryptWithoutHashInner(string plainText, string? key)
   {
      key ??= Key;
      if (plainText == "")
      {
         return [];
      }

      ArgumentNullException.ThrowIfNull(key);

      using var aesAlg = Aes.Create();
      aesAlg.KeySize = KeySize;
      aesAlg.Padding = PaddingMode.PKCS7;
      aesAlg.Key = Convert.FromBase64String(key);

      var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

      using var msEncrypt = new MemoryStream();
      using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
      using var swEncrypt = new StreamWriter(csEncrypt);
      swEncrypt.Write(plainText);
      swEncrypt.Flush();
      csEncrypt.FlushFinalBlock();

      var encryptedPasswordByte = msEncrypt.ToArray();

      var result = aesAlg.IV
                         .Concat(encryptedPasswordByte)
                         .ToArray();
      return result;
   }

   public static string Decrypt(byte[] cipherText)
   {
      return cipherText.Length == 0
         ? ""
         : DecryptSkippingHashInner(cipherText);
   }

   public static string DecryptWithoutHash(byte[] cipherText)
   {
      return cipherText.Length == 0
         ? ""
         : DecryptWithoutSkippingHashInner(cipherText, null);
   }

   public static string Decrypt(byte[] cipherText, string key)
   {
      ValidateKey(key);
      return cipherText.Length == 0
         ? ""
         : DecryptSkippingHashInner(cipherText, key);
   }

   public static string DecryptWithoutHash(byte[] cipherText, string key)
   {
      ValidateKey(key);
      return cipherText.Length == 0
         ? ""
         : DecryptWithoutSkippingHashInner(cipherText, key);
   }

   public static void Decrypt(Stream inputStream, Stream outputStream, string? key = null)
   {
      key ??= Key;
      ValidateKey(key);

      var iv = new byte[IvSize];
      if (inputStream.Read(iv, 0, IvSize) != IvSize)
      {
         throw new ArgumentException("Input stream does not contain a complete IV.");
      }

      using var aesAlg = Aes.Create();
      aesAlg.KeySize = KeySize;
      aesAlg.Padding = PaddingMode.PKCS7;
      aesAlg.Key = Convert.FromBase64String(key);
      aesAlg.IV = iv;

      using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
      using var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read, true);
      cryptoStream.CopyTo(outputStream);
   }

   private static string DecryptWithoutSkippingHashInner(byte[] cipherText, string? key)
   {
      key ??= Key;
      if (cipherText.Length == 0)
      {
         return "";
      }

      ArgumentNullException.ThrowIfNull(key);

      var iv = cipherText.Take(IvSize)
                         .ToArray();
      var encrypted = cipherText.Skip(IvSize)
                                .ToArray();

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

   internal static void RegisterKey(string key)
   {
      ValidateKey(key);
      Key = key;
   }

   private static string DecryptSkippingHashInner(IEnumerable<byte> cipherTextWithHash, string? key = null)
   {
      key ??= Key;
      var cipherText = cipherTextWithHash.Skip(HashSize)
                                         .ToArray();
      return DecryptWithoutSkippingHashInner(cipherText, key);
   }

   private static void ValidateKey([NotNull] string? key)
   {
      if (string.IsNullOrEmpty(key) || !IsBase64String(key) || Convert.FromBase64String(key)
                                                                      .Length != 32)
      {
         throw new ArgumentException("Invalid key.");
      }
   }

   private static bool IsBase64String(string s)
   {
      var buffer = new Span<byte>(new byte[s.Length]);
      return Convert.TryFromBase64String(s, buffer, out _);
   }
}