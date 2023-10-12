using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace PandatechCrypto
{
    public static class Argon2Id
    {
        private const int SaltSize = 16;
        private const int DegreeOfParallelism = 8;
        private const int Iterations = 5;
        private const int MemorySize = 128 * 1024; // 256 MB

        private static byte[] CreateSalt()
        {
            using var rng = RandomNumberGenerator.Create();
            var buffer = new byte[SaltSize];
            rng.GetBytes(buffer);
            return buffer;
        }

        public static byte[] HashPassword(string password)
        {
            var salt = CreateSalt();

            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = DegreeOfParallelism,
                Iterations = Iterations,
                MemorySize = MemorySize
            };

            var result = salt.Concat(argon2.GetBytes(32)).ToArray();

            return result;
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

            var result = salt.Concat(argon2.GetBytes(32)).ToArray();

            return result;
        }

        public static bool VerifyHash(string password, byte[] hash)
        {
            var salt = hash.Take(SaltSize).ToArray();

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