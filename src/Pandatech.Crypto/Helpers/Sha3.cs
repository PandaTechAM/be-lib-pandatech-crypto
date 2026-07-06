using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Pandatech.Crypto.Helpers;

/// <summary>
///     Keccak-512 hashing and verification.
/// </summary>
public static class Sha3
{
    /// <summary>
    ///     Hash a UTF-8 string with Keccak-512.
    /// </summary>
    public static byte[] Hash(string data)
    {
        var bytes = Encoding.UTF8.GetBytes(data);

        var digest = new KeccakDigest(512);
        digest.BlockUpdate(bytes, 0, bytes.Length);

        var result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }

    /// <summary>
    ///     Hash bytes with Keccak-512.
    /// </summary>
    public static byte[] Hash(byte[] bytes)
    {
        var digest = new KeccakDigest(512);
        digest.BlockUpdate(bytes, 0, bytes.Length);

        var result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }

    /// <summary>
    ///     Verify that a string matches a previously computed hash using constant-time comparison.
    /// </summary>
    public static bool VerifyHash(string data, byte[] hash)
    {
        var newHash = Hash(data);

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
