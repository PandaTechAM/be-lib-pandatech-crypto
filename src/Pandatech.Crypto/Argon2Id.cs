using System.Text;
using Konscious.Security.Cryptography;

namespace Pandatech.Crypto;

public class Argon2Id
{
    private readonly Argon2IdOptions _options;

    public Argon2Id(Argon2IdOptions options)
    {
        _options = options;
    }

    public Argon2Id()
    {
        _options = new Argon2IdOptions();
    }

    private const int SaltSize = 16;


    public byte[] HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        }

        var salt = Random.GenerateBytes(_options.SaltSize);
        return HashPassword(password, salt);
    }

    private byte[] HashPassword(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = _options.DegreeOfParallelism,
            Iterations = _options.Iterations,
            MemorySize = _options.MemorySize
        };

        var result = salt.Concat(argon2.GetBytes(32)).ToArray();

        return result;
    }

    public bool VerifyHash(string password, byte[] hash)
    {
        if (hash == null || hash.Length <= _options.SaltSize)
        {
            throw new ArgumentException($"Hash must be at least {SaltSize} bytes.", nameof(hash));
        }

        var salt = hash.Take(_options.SaltSize).ToArray();

        var newHash = HashPassword(password, salt);
        return ConstantTimeComparison(hash, newHash);
    }

    public bool VerifyHash(byte[] passwordHash, byte[] hash)
    {
        if (hash == null || hash.Length <= _options.SaltSize)
        {
            throw new ArgumentException($"Hash must be at least {SaltSize} bytes.", nameof(hash));
        }

        return ConstantTimeComparison(hash, passwordHash);
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