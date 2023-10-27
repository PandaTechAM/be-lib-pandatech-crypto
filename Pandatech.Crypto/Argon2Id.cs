using System.Text;
using Konscious.Security.Cryptography;

namespace Pandatech.Crypto;

public static class Argon2Id
{
    private const int SaltSize = 16;
    private const int DegreeOfParallelism = 8;
    private const int Iterations = 5;
    private const int MemorySize = 128 * 1024; // 128 MB


    public static byte[] HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        }
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

        var result = salt.Concat(argon2.GetBytes(32)).ToArray();

        return result;
    }

    public static bool VerifyHash(string password, byte[] hash)
    {
        if (hash == null || hash.Length <= SaltSize)
        {
            throw new ArgumentException($"Hash must be at least {SaltSize} bytes.", nameof(hash));
        }
        
        var salt = hash.Take(SaltSize).ToArray();

        var newHash = HashPassword(password, salt);
        return ConstantTimeComparison(hash, newHash);
    }

    private static bool ConstantTimeComparison(IReadOnlyList<byte> a, IReadOnlyList<byte> b)
    {
        var diff = (ushort)a.Count ^ (ushort)b.Count;
        for (var i = 0; i < a.Count && i < b.Count; i++)
        {
            diff |= (ushort)(a[i] ^ b[i]);
        }

        return diff == 0;
    }
}