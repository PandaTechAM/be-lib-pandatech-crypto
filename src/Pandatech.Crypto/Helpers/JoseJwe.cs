using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jose;

namespace Pandatech.Crypto.Helpers;

public static class JoseJwe
{
   public static (string PublicJwk, string PrivateJwk, string Kid) IssueKeys(int bits = 2048)
   {
      if (bits < 2048)
      {
         throw new ArgumentOutOfRangeException(nameof(bits), "RSA key must be >= 2048 bits.");
      }

      using var rsa = RSA.Create(bits);
      var pubJwk = ExportPublicJwk(rsa);
      var prvJwk = ExportPrivateJwk(rsa);
      var kid = Thumbprint(pubJwk);
      return (pubJwk, prvJwk, kid);
   }

   public static string Encrypt(string publicJwk, byte[] payload, string kid)
   {
      // Validate kid matches public key
      var computed = Thumbprint(publicJwk);
      if (!string.Equals(computed, kid, StringComparison.Ordinal))
      {
         throw new ArgumentException("kid does not match publicJwk (RFC7638).", nameof(kid));
      }

      using var rsa = ImportPublic(publicJwk);

      // JWE: RSA-OAEP-256 + A256GCM; compact serialization; header includes kid
      return JWT.EncodeBytes(
         payload,
         rsa,
         JweAlgorithm.RSA_OAEP_256,
         JweEncryption.A256GCM,
         extraHeaders: new Dictionary<string, object>
         {
            ["kid"] = kid
         }
      );
   }

   public static bool TryDecrypt(string privateJwk, string jwe, out byte[] payload)
   {
      try
      {
         using var rsa = ImportPrivate(privateJwk);
         payload = JWT.DecodeBytes(jwe, rsa, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);
         return true;
      }
      catch
      {
         payload = [];
         return false;
      }
   }

   public static string ComputeKid(string publicJwk)
   {
      return Thumbprint(publicJwk);
   }

   private static RSA ImportPublic(string jwkJson)
   {
      using var doc = JsonDocument.Parse(jwkJson);
      var r = doc.RootElement;
      if (r.GetProperty("kty")
           .GetString() != "RSA")
      {
         throw new ArgumentException("kty must be RSA.");
      }

      var n = Base64Url.Decode(r.GetProperty("n")
                                .GetString()!);

      if (n.Length * 8 < 2048)
      {
         throw new CryptographicException("RSA public key must be >= 2048 bits.");
      }

      var e = Base64Url.Decode(r.GetProperty("e")
                                .GetString()!);
      var p = new RSAParameters
      {
         Modulus = n,
         Exponent = e
      };
      var rsa = RSA.Create();
      rsa.ImportParameters(p);
      return rsa;
   }

   private static RSA ImportPrivate(string jwkJson)
   {
      using var doc = JsonDocument.Parse(jwkJson);
      var r = doc.RootElement;
      if (r.GetProperty("kty")
           .GetString() != "RSA")
      {
         throw new ArgumentException("kty must be RSA.");
      }

      var n = Base64Url.Decode(r.GetProperty("n")
                                .GetString()!);
      if (n.Length * 8 < 2048)
      {
         throw new CryptographicException("RSA private key must be >= 2048 bits.");
      }

      var pars = new RSAParameters
      {
         Modulus = Base64Url.Decode(r.GetProperty("n")
                                     .GetString()!),

         Exponent = Base64Url.Decode(r.GetProperty("e")
                                      .GetString()!),
         D = Base64Url.Decode(r.GetProperty("d")
                               .GetString()!)
      };

      // optional CRT params if present
      Try(r, "p", out pars.P);
      Try(r, "q", out pars.Q);
      Try(r, "dp", out pars.DP);
      Try(r, "dq", out pars.DQ);
      Try(r, "qi", out pars.InverseQ);

      var rsa = RSA.Create();
      rsa.ImportParameters(pars);
      return rsa;

      static void Try(JsonElement root, string name, out byte[]? val)
      {
         val = root.TryGetProperty(name, out var v) ? Base64Url.Decode(v.GetString()!) : null;
      }
   }

   private static string ExportPublicJwk(RSA rsa)
   {
      var p = rsa.ExportParameters(false);
      var o = new
      {
         kty = "RSA",
         n = Base64Url.Encode(p.Modulus!),
         e = Base64Url.Encode(p.Exponent!)
      };
      return JsonSerializer.Serialize(o);
   }

   private static string ExportPrivateJwk(RSA rsa)
   {
      var p = rsa.ExportParameters(true);
      var o = new
      {
         kty = "RSA",
         n = Base64Url.Encode(p.Modulus!),
         e = Base64Url.Encode(p.Exponent!),
         d = Base64Url.Encode(p.D!),
         p = p.P is null ? null : Base64Url.Encode(p.P),
         q = p.Q is null ? null : Base64Url.Encode(p.Q),
         dp = p.DP is null ? null : Base64Url.Encode(p.DP),
         dq = p.DQ is null ? null : Base64Url.Encode(p.DQ),
         qi = p.InverseQ is null ? null : Base64Url.Encode(p.InverseQ)
      };
      var json = JsonSerializer.Serialize(o);
      // remove nulls (compact)
      using var doc = JsonDocument.Parse(json);
      using var ms = new MemoryStream();
      using var w = new Utf8JsonWriter(ms);
      w.WriteStartObject();
      foreach (var prop in doc.RootElement
                              .EnumerateObject()
                              .Where(prop => prop.Value.ValueKind != JsonValueKind.Null))
      {
         prop.WriteTo(w);
      }

      w.WriteEndObject();
      w.Flush();
      return Encoding.UTF8.GetString(ms.ToArray());
   }

   // RFC 7638 thumbprint over {"e","kty","n"} with lexicographic keys
   private static string Thumbprint(string publicRsaJwk)
   {
      using var doc = JsonDocument.Parse(publicRsaJwk);
      var r = doc.RootElement;
      var canonical =
         $$"""{"e":"{{r.GetProperty("e").GetString()}}" ,"kty":"RSA","n":"{{r.GetProperty("n").GetString()}}"}"""
            .Replace(" ", "");
      var hash = SHA256.HashData(Encoding.ASCII.GetBytes(canonical));
      return Base64Url.Encode(hash);
   }
}