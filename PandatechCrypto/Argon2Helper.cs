using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace PandatechCrypto
{
    public static class Argon2Helper
    {
        public static byte[] CreateSalt()
        {
            using var rng = RandomNumberGenerator.Create();
            var buffer = new byte[16];
            rng.GetBytes(buffer);
            return buffer;
        }

        public static byte[] HashPassword(string password, byte[] salt, int memorySize = 128 * 1024)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = 4,
                Iterations = 4,
                MemorySize = 256 * 1024

            };

            return argon2.GetBytes(32);
        }

        public static bool VerifyHash(string password, byte[] salt, byte[] hash)
        {
            var newHash = HashPassword(password, salt);
            return ConstantTimeComparison(hash, newHash);
        }

        private static bool ConstantTimeComparison(byte[] a, byte[] b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;
            for (var i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }
    }
}