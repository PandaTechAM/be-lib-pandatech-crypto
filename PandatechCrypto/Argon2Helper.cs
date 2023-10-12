using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace PandatechCrypto
{
    public static class Argon2Helper
    {
        private static byte[] CreateSalt()
        {
            using var rng = RandomNumberGenerator.Create();
            var buffer = new byte[16];
            rng.GetBytes(buffer);
            return buffer;
        }

        public static byte[] HashPassword(string password)
        {
            var salt = CreateSalt();

            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = 4,
                Iterations = 4,
                MemorySize = 256 * 1024

            };

            var result = salt.Concat(argon2.GetBytes(32)).ToArray();

            return result;
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = 4,
                Iterations = 4,
                MemorySize = 256 * 1024

            };

            var result = salt.Concat(argon2.GetBytes(32)).ToArray();

            return result;
        }

        public static bool VerifyHash(string password, byte[] hash)
        {
            byte[] salt = hash.Skip(16).ToArray();

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