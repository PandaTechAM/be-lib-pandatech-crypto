using System.Security.Cryptography;

namespace Pandatech.Cryptos;

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
}