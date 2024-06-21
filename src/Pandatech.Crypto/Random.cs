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

    public static long GenerateIdWithVariableSequence(long previousId, int approximateSequenceVariability = 100)
    {
        var minimumRandRange = approximateSequenceVariability / 25;
        var random = System.Random.Shared.NextInt64(minimumRandRange, approximateSequenceVariability + 1);
        
        return (previousId + random);
    }
}