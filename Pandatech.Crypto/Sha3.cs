using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Pandatech.Crypto;

public static class Sha3
{
    public static byte[] Hash(string data)
    {
        var bytes = Encoding.UTF8.GetBytes(data);
        
        var digest = new KeccakDigest(512);
        digest.BlockUpdate(bytes, 0, bytes.Length);
        
        var result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        
        return result;
    }
    
    public static bool VerifyHash(string data, byte[] hash)
    {
        var newHash = Hash(data);
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