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

public static class Aes256Siv
{
   private static string? GlobalKey { get; set; }

   internal static void RegisterKey(string key)
   {
      ValidateKey(key);
      GlobalKey = key;
   }

   // --- Simple API (no AD) -------------------------------------------------

   public static byte[] Encrypt(string plaintext)
   {
      return Encrypt(Encoding.UTF8.GetBytes(plaintext), null);
   }

   public static byte[] Encrypt(string plaintext, string? key)
   {
      return Encrypt(Encoding.UTF8.GetBytes(plaintext), key);
   }

   public static byte[] Encrypt(byte[] plaintext)
   {
      return Encrypt(plaintext, null);
   }

   public static byte[] Encrypt(byte[] plaintext, string? key)
   {
      var keyBytes = GetKeyBytes(key);
      var macKey = keyBytes.AsSpan(0, 16);
      var encKey = keyBytes.AsSpan(16, 16);

      var v = ComputeS2V(macKey, plaintext); // 16 bytes
      var q = MaskForCtr(v); // masked V
      var c = AesCtr(encKey, q, plaintext);
      return Arrays.Concatenate(v, c);
   }

   public static string Decrypt(byte[] ciphertext)
   {
      return Decrypt(ciphertext, null);
   }

   public static string Decrypt(byte[] ciphertext, string? key)
   {
      return Encoding.UTF8.GetString(DecryptToBytes(ciphertext, key));
   }

   public static byte[] DecryptToBytes(byte[] ciphertext)
   {
      return DecryptToBytes(ciphertext, null);
   }

   public static byte[] DecryptToBytes(byte[] ciphertext, string? key)
   {
      if (ciphertext.Length < 16)
      {
         return [];
      }

      var keyBytes = GetKeyBytes(key);

      var macKey = keyBytes.AsSpan(0, 16);
      var encKey = keyBytes.AsSpan(16, 16);

      var v = ciphertext[..16];
      var enc = ciphertext[16..];
      var q = MaskForCtr(v);

      var plain = AesCtr(encKey, q, enc);
      var expectedV = ComputeS2V(macKey, plain);

      return !CryptographicOperations.FixedTimeEquals(v, expectedV)
         ? throw new CryptographicException("Invalid SIV / authentication tag.")
         : plain;
   }

   // --- SIV core (RFC 5297; single-string, no AD) --------------------------

   private static byte[] ComputeS2V(ReadOnlySpan<byte> macKey, ReadOnlySpan<byte> data)
   {
      var cmac = new CMac(new AesEngine());
      cmac.Init(new KeyParameter(macKey.ToArray()));

      // D = CMAC(0^128)
      var D = CmacHash(cmac, new byte[16]);

      if (data.Length >= 16)
      {
         // T = CMAC( M[0..n-16) || (M_last16 XOR D) )
         cmac.Reset();
         if (data.Length > 16)
         {
            cmac.BlockUpdate(data[..^16]
                  .ToArray(),
               0,
               data.Length - 16);
         }

         var last = data[^16..]
            .ToArray();
         for (var i = 0; i < 16; i++)
         {
            last[i] ^= D[i];
         }

         cmac.BlockUpdate(last, 0, 16);

         var outT = new byte[cmac.GetMacSize()];
         cmac.DoFinal(outT, 0);
         return outT;
      }

      // T = CMAC( pad(M) XOR dbl(D) )
      var dblD = DoubleBlock(D);
      var block = Pad(data);
      for (var i = 0; i < 16; i++)
      {
         block[i] ^= dblD[i];
      }

      return CmacHash(cmac, block);
   }

   private static byte[] MaskForCtr(ReadOnlySpan<byte> v)
   {
      // Q = V with two bits cleared (per RFC 5297 §2.6)
      var q = v.ToArray();
      // Clear the MSB of byte 8 and byte 12 (correspond to bits 63 and 31)
      q[8] &= 0x7F;
      q[12] &= 0x7F;
      return q;
   }

   private static byte[] AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input)
   {
      var cipher = new BufferedBlockCipher(new SicBlockCipher(new AesEngine()));
      cipher.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), iv.ToArray()));
      return cipher.DoFinal(input.ToArray());
   }

   private static byte[] CmacHash(IMac cmac, byte[] input)
   {
      cmac.Reset();
      cmac.BlockUpdate(input, 0, input.Length);
      var output = new byte[cmac.GetMacSize()];
      cmac.DoFinal(output, 0);
      return output;
   }

   private static byte[] Pad(ReadOnlySpan<byte> input)
   {
      var padded = new byte[16];
      if (!input.IsEmpty)
      {
         input.CopyTo(padded);
      }

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
      {
         output[15] ^= 0x87;
      }

      return output;
   }

   // --- key plumbing --------------------------------------------------------

   private static byte[] GetKeyBytes(string? overrideKey)
   {
      if (string.IsNullOrEmpty(overrideKey))
      {
         return GlobalKey is null
            ? throw new InvalidOperationException("AES256 Key not configured. Call RegisterKey(...) or provide a key.")
            : Convert.FromBase64String(GlobalKey);
      }

      ValidateKey(overrideKey);
      return Convert.FromBase64String(overrideKey);
   }

   private static void ValidateKey([NotNull] string? key)
   {
      if (string.IsNullOrWhiteSpace(key) || !IsBase64String(key))
      {
         throw new ArgumentException("Key must be valid Base64.");
      }

      if (Convert.FromBase64String(key)
                 .Length != 32)
      {
         throw new ArgumentException("Key must be 32 bytes (256 bits).");
      }
   }

   private static bool IsBase64String(string input)
   {
      var buffer = new Span<byte>(new byte[input.Length]);
      return Convert.TryFromBase64String(input, buffer, out _);
   }
}