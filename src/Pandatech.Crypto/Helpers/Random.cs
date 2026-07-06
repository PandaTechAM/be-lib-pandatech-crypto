using System.Security.Cryptography;

namespace Pandatech.Crypto.Helpers;

/// <summary>
///     Secure random value generators.
/// </summary>
public static class Random
{
    /// <summary>
    ///     Generate cryptographically secure random bytes.
    /// </summary>
    public static byte[] GenerateBytes(int length)
    {
        using var rng = RandomNumberGenerator.Create();
        var buffer = new byte[length];
        rng.GetBytes(buffer);
        return buffer;
    }

    /// <summary>
    ///     Generate a random 256-bit AES key as a Base64 string.
    /// </summary>
    public static string GenerateAes256KeyString()
    {
        using var rng = RandomNumberGenerator.Create();
        var buffer = new byte[32];
        rng.GetBytes(buffer);
        return Convert.ToBase64String(buffer);
    }

    /// <summary>
    ///     Generate the next id by adding a random gap to the previous id, so real record counts are not guessable.
    ///     Not cryptographically secure.
    /// </summary>
    public static long GenerateIdWithVariableSequence(long previousId, int approximateSequenceVariability = 100)
    {
        var minimumRandRange = approximateSequenceVariability / 25;
        var random = System.Random.Shared.NextInt64(minimumRandRange, approximateSequenceVariability + 1);

        return previousId + random;
    }

    /// <summary>
    ///     Generate a URL-safe random token with 256 bits of entropy.
    /// </summary>
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

    /// <summary>
    ///     Generate a short URL-safe random string with 96 bits of entropy.
    /// </summary>
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
