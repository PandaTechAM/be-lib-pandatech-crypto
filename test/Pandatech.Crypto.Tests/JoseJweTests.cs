namespace Pandatech.Crypto.Tests;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jose;
using Helpers;
using Xunit;

public class JoseJweTests
{
   [Fact]
   public void IssueKeys_Default_GeneratesValidJwks_And_KidMatches()
   {
      var (pub, prv, kid) = JoseJwe.IssueKeys(); // 2048
      Assert.False(string.IsNullOrWhiteSpace(pub));
      Assert.False(string.IsNullOrWhiteSpace(prv));
      Assert.False(string.IsNullOrWhiteSpace(kid));

      using var pubDoc = JsonDocument.Parse(pub);
      using var prvDoc = JsonDocument.Parse(prv);

      Assert.Equal("RSA",
         pubDoc.RootElement
               .GetProperty("kty")
               .GetString());
      Assert.Equal("RSA",
         prvDoc.RootElement
               .GetProperty("kty")
               .GetString());
      Assert.True(pubDoc.RootElement.TryGetProperty("n", out _));
      Assert.True(pubDoc.RootElement.TryGetProperty("e", out _));
      Assert.True(prvDoc.RootElement.TryGetProperty("d", out _));

      // Kid must be RFC7638 thumbprint of pub JWK
      Assert.Equal(kid, JoseJwe.ComputeKid(pub));
   }

   [Fact]
   public void IssueKeys_Rejects_ShortKey()
   {
      var ex = Assert.Throws<ArgumentOutOfRangeException>(() => JoseJwe.IssueKeys(1024));
      Assert.Contains(">= 2048", ex.Message);
   }

   [Fact]
   public void Encrypt_And_TryDecrypt_RoundTrip_Succeeds()
   {
      var (pub, prv, kid) = JoseJwe.IssueKeys();
      var payload = "hello-jwe"u8.ToArray();

      var jwe = JoseJwe.Encrypt(pub, payload, kid);

      Assert.True(JoseJwe.TryDecrypt(prv, jwe, out var plain));
      Assert.Equal(payload, plain);
   }

   [Fact]
   public void Encrypt_Includes_Header_Kid_And_AlgEnc()
   {
      var (pub, prv, kid) = JoseJwe.IssueKeys();
      var jwe = JoseJwe.Encrypt(pub, [], kid);

      var hdr = JWT.Headers(jwe); // jose-jwt parses compact JWE header
      Assert.Equal("RSA-OAEP-256", hdr["alg"]);
      Assert.Equal("A256GCM", hdr["enc"]);
      Assert.Equal(kid, hdr["kid"]);
   }

   [Fact]
   public void Encrypt_With_MismatchedKid_Throws()
   {
      var (pub1, _, _) = JoseJwe.IssueKeys();
      var (_, _, kid2) = JoseJwe.IssueKeys();

      var data = "x"u8.ToArray();
      // wrong kid for the provided public key
      var ex = Assert.Throws<ArgumentException>(() => JoseJwe.Encrypt(pub1, data, kid2));
      Assert.Contains("kid does not match", ex.Message);
   }

   [Fact]
   public void TryDecrypt_With_WrongKey_ReturnsFalse()
   {
      var (pub1, prv1, kid1) = JoseJwe.IssueKeys();
      var (pub2, prv2, _) = JoseJwe.IssueKeys();

      var jwe = JoseJwe.Encrypt(pub1, "abc"u8.ToArray(), kid1);

      Assert.True(JoseJwe.TryDecrypt(prv1, jwe, out var ok));
      Assert.Equal("abc", Encoding.UTF8.GetString(ok));

      Assert.False(JoseJwe.TryDecrypt(prv2, jwe, out _));
   }

   [Fact]
   public void TryDecrypt_With_InvalidJwe_ReturnsFalse()
   {
      var (_, prv, _) = JoseJwe.IssueKeys();
      Assert.False(JoseJwe.TryDecrypt(prv, "not-a-jwe", out _));
   }

   [Fact]
   public void Encrypt_With_Short_PublicKey_Throws_CryptographicException()
   {
      // Build a 1024-bit RSA public JWK to hit ImportPublic() size guard
      using var rsa1024 = RSA.Create(1024);
      var p = rsa1024.ExportParameters(false);
      var pubJwk1024 = JsonSerializer.Serialize(new
      {
         kty = "RSA",
         n = Base64Url.Encode(p.Modulus!),
         e = Base64Url.Encode(p.Exponent!)
      });
      var kid = JoseJwe.ComputeKid(pubJwk1024);
      var data = "x"u8.ToArray();

      var ex = Assert.Throws<CryptographicException>(() => JoseJwe.Encrypt(pubJwk1024, data, kid));
      Assert.Contains(">= 2048", ex.Message);
   }

   [Fact]
   public void TryDecrypt_With_Short_PrivateKey_ReturnsFalse()
   {
      // Build a 1024-bit RSA private JWK to hit ImportPrivate() size guard (caught by TryDecrypt)
      using var rsa1024 = RSA.Create(1024);
      var p = rsa1024.ExportParameters(true);
      var prvJwk1024 = SerializePrivateJwk(p);

      // Any JWE string is fine; ImportPrivate fails first and TryDecrypt returns false
      Assert.False(JoseJwe.TryDecrypt(prvJwk1024, "aaaa.bbbb.cccc.dddd.eeee", out _));
   }

   [Fact]
   public void Encrypt_EmptyPayload_Then_Decrypt_Succeeds()
   {
      var (pub, prv, kid) = JoseJwe.IssueKeys();
      var jwe = JoseJwe.Encrypt(pub, [], kid);
      Assert.True(JoseJwe.TryDecrypt(prv, jwe, out var plain));
      Assert.Empty(plain);
   }

   // ---- helpers ----

   private static string SerializePrivateJwk(RSAParameters p)
   {
      var o = new Dictionary<string, object?>
      {
         ["kty"] = "RSA",
         ["n"] = Base64Url.Encode(p.Modulus!),
         ["e"] = Base64Url.Encode(p.Exponent!),
         ["d"] = Base64Url.Encode(p.D!)
      };
      if (p.P is not null) o["p"] = Base64Url.Encode(p.P);
      if (p.Q is not null) o["q"] = Base64Url.Encode(p.Q);
      if (p.DP is not null) o["dp"] = Base64Url.Encode(p.DP);
      if (p.DQ is not null) o["dq"] = Base64Url.Encode(p.DQ);
      if (p.InverseQ is not null) o["qi"] = Base64Url.Encode(p.InverseQ);

      return JsonSerializer.Serialize(o);
   }
}