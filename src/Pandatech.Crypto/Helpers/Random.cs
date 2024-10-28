using System.Security.Cryptography;

namespace Pandatech.Crypto.Helpers;

public static class Random
{
   public static byte[] GenerateBytes(int length)
   {
      using var rng = RandomNumberGenerator.Create();
      var buffer = new byte[length];
      rng.GetBytes(buffer);
      return buffer;
   }

   public static string GenerateAes256KeyString()
   {
      using var rng = RandomNumberGenerator.Create();
      var buffer = new byte[32];
      rng.GetBytes(buffer);
      return Convert.ToBase64String(buffer);
   }

   public static long GenerateIdWithVariableSequence(long previousId, int approximateSequenceVariability = 100)
   {
      var minimumRandRange = approximateSequenceVariability / 25;
      var random = System.Random.Shared.NextInt64(minimumRandRange, approximateSequenceVariability + 1);

      return previousId + random;
   }

   public static string GenerateSecureToken()
   {
      const int length = 32; // 32 bytes = 256 bits
      var bytes = new byte[length];
      using (var rng = RandomNumberGenerator.Create())
      {
         rng.GetBytes(bytes);
      }

      return Convert.ToBase64String(bytes)
                    .Replace("+", "-") // Make URL-safe
                    .Replace("/", "_") // Make URL-safe
                    .TrimEnd('='); // Remove padding
   }

   public static string GenerateShortUniqueString()
   {
      const int length = 12; // 12 bytes = 96 bits
      var bytes = new byte[length];
      using (var rng = RandomNumberGenerator.Create())
      {
         rng.GetBytes(bytes);
      }

      return Convert.ToBase64String(bytes)
                    .Replace("+", "-") // Make URL-safe
                    .Replace("/", "_") // Make URL-safe
                    .TrimEnd('='); // Remove padding
   }
}