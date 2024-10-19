using System.Security.Cryptography;
using System.Text;

namespace Pandatech.Crypto;

public static class Sha2
{
   public static byte[] ComputeHmacSha256(byte[] key, params string[] messages)
   {
      using var hmac = new HMACSHA256(key);

      var concatenatedMessage = Encoding.UTF8.GetBytes(string.Concat(messages));
      return hmac.ComputeHash(concatenatedMessage);
   }

   public static string GetHmacSha256Hex(byte[] key, params string[] messages)
   {
      var hash = ComputeHmacSha256(key, messages);
      return BitConverter.ToString(hash).Replace("-", "").ToLower();
   }
   
   public static string GetHmacSha256Base64(byte[] key, params string[] messages)
   {
      var hash = ComputeHmacSha256(key, messages);
      return Convert.ToBase64String(hash);
   }
}