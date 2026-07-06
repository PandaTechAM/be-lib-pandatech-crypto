using System.Security.Cryptography;
using System.Text;

namespace Pandatech.Crypto.Helpers;

/// <summary>
///     HMAC-SHA256 hashing helpers.
/// </summary>
public static class Sha2
{
    /// <summary>
    ///     Compute an HMAC-SHA256 over the concatenated messages using a byte-array key.
    /// </summary>
    public static byte[] ComputeHmacSha256(byte[] key, params string[] messages)
    {
        using var hmac = new HMACSHA256(key);

        var concatenatedMessage = Encoding.UTF8.GetBytes(string.Concat(messages));
        return hmac.ComputeHash(concatenatedMessage);
    }

    /// <summary>
    ///     Compute an HMAC-SHA256 over the concatenated messages using a UTF-8 string key.
    /// </summary>
    public static byte[] ComputeHmacSha256(string key, params string[] messages)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        return ComputeHmacSha256(keyBytes, messages);
    }

    /// <summary>
    ///     Compute an HMAC-SHA256 and return it as a lowercase hex string.
    /// </summary>
    public static string GetHmacSha256Hex(byte[] key, params string[] messages)
    {
        var hash = ComputeHmacSha256(key, messages);
        return BitConverter.ToString(hash)
            .Replace("-", "")
            .ToLower();
    }

    /// <summary>
    ///     Compute an HMAC-SHA256 and return it as a Base64 string.
    /// </summary>
    public static string GetHmacSha256Base64(byte[] key, params string[] messages)
    {
        var hash = ComputeHmacSha256(key, messages);
        return Convert.ToBase64String(hash);
    }
}
