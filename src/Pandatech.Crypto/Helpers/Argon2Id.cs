using System.Text;
using Konscious.Security.Cryptography;

namespace Pandatech.Crypto.Helpers;

public static class Argon2Id
{
   internal static int SaltSize { get; private set; } = 16;
   internal static int DegreeOfParallelism { get; private set; } = 8;
   internal static int Iterations { get; private set; } = 5;
   internal static int MemorySize { get; private set; } = 128 * 1024; // 128 MB


   public static byte[] HashPassword(string password)
   {
      var salt = Random.GenerateBytes(SaltSize);
      return HashPassword(password, salt);
   }

   private static byte[] HashPassword(string password, byte[] salt)
   {
      using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
      {
         Salt = salt,
         DegreeOfParallelism = DegreeOfParallelism,
         Iterations = Iterations,
         MemorySize = MemorySize
      };

      var result = salt.Concat(argon2.GetBytes(32))
                       .ToArray();

      return result;
   }

   public static bool VerifyHash(string password, byte[] passwordHash)
   {
      if (passwordHash.Length <= SaltSize)
      {
         throw new ArgumentException($"Hash must be at least {SaltSize} bytes.", nameof(passwordHash));
      }

      var salt = passwordHash.Take(SaltSize)
                             .ToArray();

      var newHash = HashPassword(password, salt);
      return ConstantTimeComparison(passwordHash, newHash);
   }

   private static bool ConstantTimeComparison(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
   {
      if (a.Length != b.Length)
      {
         return false;
      }

      var diff = 0;
      for (var i = 0; i < a.Length; i++)
      {
         diff |= a[i] ^ b[i];
      }

      return diff == 0;
   }

   internal static void Configure(Argon2IdOptions options)
   {
      SaltSize = options.SaltSize;
      DegreeOfParallelism = options.DegreeOfParallelism;
      Iterations = options.Iterations;
      MemorySize = options.MemorySize;
   }
}