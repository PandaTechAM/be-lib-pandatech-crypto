using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Pandatech.Crypto.Helpers;

[Obsolete("This is a legacy implementation of AES256-SIV. Use Aes256Siv instead.", false)]
public static class Aes256SivLegacy
{
   private static string? GlobalKey { get; set; }

   internal static void RegisterKey(string key)
   {
      ValidateKey(key);
      GlobalKey = key;
   }

   public static byte[] Encrypt(string plaintext)
   {
      return Encrypt(plaintext, null);
   }

   public static byte[] Encrypt(string plaintext, string? key = null)
   {
      var bytes = Encoding.UTF8.GetBytes(plaintext);
      return Encrypt(bytes, key);
   }

   public static byte[] Encrypt(byte[] plaintext)
   {
      return Encrypt(plaintext, null);
   }

   public static byte[] Encrypt(byte[] plaintext, string? key = null)
   {
      if (plaintext.Length == 0)
      {
         return [];
      }

      var keyBytes = GetKeyBytes(key);
      var macKey = keyBytes[..16];
      var encKey = keyBytes[16..];

      var siv = ComputeS2V(macKey, plaintext);
      var cipher = AesCtr(encKey, siv, plaintext);
      return Arrays.Concatenate(siv, cipher);
   }

   public static void Encrypt(Stream input, Stream output)
   {
      Encrypt(input, output, null);
   }

   public static void Encrypt(Stream input, Stream output, string? key = null)
   {
      ArgumentNullException.ThrowIfNull(input);
      ArgumentNullException.ThrowIfNull(output);

      using var ms = new MemoryStream();
      input.CopyTo(ms);
      var encrypted = Encrypt(ms.ToArray(), key);
      output.Write(encrypted, 0, encrypted.Length);
   }

   public static string Decrypt(byte[] ciphertext)
   {
      return Decrypt(ciphertext, null);
   }

   public static string Decrypt(byte[] ciphertext, string? key = null)
   {
      var plain = DecryptToBytes(ciphertext, key);
      return Encoding.UTF8.GetString(plain);
   }

   public static byte[] DecryptToBytes(byte[] ciphertext)
   {
      return DecryptToBytes(ciphertext, null);
   }

   public static byte[] DecryptToBytes(byte[] ciphertext, string? key = null)
   {
      var keyBytes = GetKeyBytes(key);

      switch (ciphertext.Length)
      {
         case 0:
            return [];
         case < 16:
            throw new ArgumentException("At least 16 bytes are required for the SIV.");
      }

      var macKey = keyBytes[..16];
      var encKey = keyBytes[16..];

      var siv = ciphertext[..16];
      var encrypted = ciphertext[16..];

      var plain = AesCtr(encKey, siv, encrypted);
      var expectedSiv = ComputeS2V(macKey, plain);

      return !CryptographicOperations.FixedTimeEquals(siv, expectedSiv)
         ? throw new CryptographicException("Invalid SIV / authentication tag.")
         : plain;
   }

   public static void Decrypt(Stream input, Stream output)
   {
      Decrypt(input, output, null);
   }

   public static void Decrypt(Stream input, Stream output, string? key = null)
   {
      ArgumentNullException.ThrowIfNull(input);
      ArgumentNullException.ThrowIfNull(output);

      using var ms = new MemoryStream();
      input.CopyTo(ms);
      var decrypted = DecryptToBytes(ms.ToArray(), key);
      output.Write(decrypted, 0, decrypted.Length);
   }

   private static byte[] ComputeS2V(byte[] macKey, byte[] data)
   {
      var cmac = new CMac(new AesEngine());
      cmac.Init(new KeyParameter(macKey));
      var D = CmacHash(cmac, new byte[16]);

      if (data.Length >= 16)
      {
         var block = new byte[16];
         Array.Copy(data, data.Length - 16, block, 0, 16);
         for (var i = 0; i < 16; i++)
            block[i] ^= D[i];
         return CmacHash(cmac, block);
      }
      else
      {
         D = DoubleBlock(D);
         var block = Pad(data);
         for (var i = 0; i < 16; i++)
            block[i] ^= D[i];
         return CmacHash(cmac, block);
      }
   }

   private static byte[] AesCtr(byte[] key, byte[] iv, byte[] input)
   {
      var cipher = new BufferedBlockCipher(new SicBlockCipher(new AesEngine()));
      cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
      return cipher.DoFinal(input);
   }

   private static byte[] CmacHash(IMac cmac, byte[] input)
   {
      cmac.Reset();
      cmac.BlockUpdate(input, 0, input.Length);
      var output = new byte[cmac.GetMacSize()];
      cmac.DoFinal(output, 0);
      return output;
   }

   private static byte[] Pad(byte[] input)
   {
      var padded = new byte[16];
      Array.Copy(input, padded, input.Length);
      padded[input.Length] = 0x80;
      return padded;
   }

   private static byte[] DoubleBlock(byte[] block)
   {
      var output = new byte[16];
      var carry = 0;
      for (var i = 15; i >= 0; i--)
      {
         var val = (block[i] & 0xFF) << 1;
         val |= carry;
         output[i] = (byte)(val & 0xFF);
         carry = (val >> 8) & 1;
      }

      if ((block[0] & 0x80) != 0)
         output[15] ^= 0x87;
      return output;
   }

   private static byte[] GetKeyBytes(string? overrideKey)
   {
      if (!string.IsNullOrEmpty(overrideKey))
      {
         ValidateKey(overrideKey);
         return Convert.FromBase64String(overrideKey);
      }

      if (GlobalKey is null)
      {
         throw new InvalidOperationException("AES256 Key not configured. Call RegisterKey(...) or provide a key.");
      }

      return Convert.FromBase64String(GlobalKey);
   }

   private static void ValidateKey([NotNull] string? key)
   {
      if (string.IsNullOrWhiteSpace(key) || !IsBase64String(key))
         throw new ArgumentException("Key must be valid Base64.");
      if (Convert.FromBase64String(key)
                 .Length != 32)
         throw new ArgumentException("Key must be 32 bytes (256 bits).");
   }

   private static bool IsBase64String(string input)
   {
      var buffer = new Span<byte>(new byte[input.Length]);
      return Convert.TryFromBase64String(input, buffer, out _);
   }
}