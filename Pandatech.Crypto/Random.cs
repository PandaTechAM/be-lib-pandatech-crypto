using System.Security.Cryptography;

namespace Pandatech.Crypto;

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

    public static long GeneratePandaId(long? previousId)
    {
        var random = GenerateBytes(4);
        var randomValue = BitConverter.ToInt32(random, 0) & 0x7FFFFFFF;
        var randomOffset = randomValue % 36 + 1;
        
        if (previousId is 0 or null)
        {
            return 1_000_000 + randomOffset;
        }

        return (long)(previousId + randomOffset)!;
    }
}