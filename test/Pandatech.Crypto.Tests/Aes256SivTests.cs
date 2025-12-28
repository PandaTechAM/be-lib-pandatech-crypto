using System.Security.Cryptography;
using Pandatech.Crypto.Helpers;
using Random = Pandatech.Crypto.Helpers.Random;

namespace Pandatech.Crypto.Tests;

public class Aes256SivTests
{
   private static string Key()
   {
      return Random.GenerateAes256KeyString();
   }

   [Theory]
   [InlineData(" ")]
   [InlineData("HelloWorld")]
   [InlineData("Some special characters: ~!@#$%^&*()_+{}|:\"<>?")]
   [InlineData("Tabs\tNewLine\nCarriageReturn\rMixed\n\rAll")]
   [InlineData("Unicode test: 你好, мир, مرحبا, नमस्ते")]
   [InlineData("Emoji test: \U0001F600 \U0001F31F \U0001F680")]
   [InlineData("1234567890")]
   [InlineData("😀😃😄😁😆")]
   [InlineData("Line1\nLine2\r\nLine3")]
   [InlineData("A string with a null char \0 in between")]
   public void EncryptDecrypt_String_RoundTrip(string original)
   {
      var key = Key();
      var cipher = Aes256Siv.Encrypt(original, key);
      var plain = Aes256Siv.Decrypt(cipher, key);
      Assert.Equal(original, plain);
   }

   [Fact]
   public void Deterministic_SamePlaintextSameCiphertext()
   {
      var key = Key();
      const string msg = "DeterministicTest";
      var c1 = Aes256Siv.Encrypt(msg, key);
      var c2 = Aes256Siv.Encrypt(msg, key);
      Assert.Equal(c1, c2);
   }

   [Fact]
   public void EmptyInput_Produces16ByteV_AndDecryptsToEmpty()
   {
      var key = Key();
      var c = Aes256Siv.Encrypt([], key);
      Assert.Equal(16, c.Length); // V only
      var p = Aes256Siv.DecryptToBytes(c, key);
      Assert.Empty(p);
   }

   [Fact]
   public void Tamper_Ciphertext_Fails()
   {
      var key = Key();
      var c = Aes256Siv.Encrypt("SomeData", key);
      c[^1] ^= 0x01;
      Assert.ThrowsAny<CryptographicException>(() => Aes256Siv.Decrypt(c, key));
   }

   [Fact]
   public void Tamper_Tag_Fails()
   {
      var key = Key();
      var c = Aes256Siv.Encrypt("SomeData", key);
      c[0] ^= 0x80; // flip bit in V
      Assert.ThrowsAny<CryptographicException>(() => Aes256Siv.Decrypt(c, key));
   }

   [Fact]
   public void InvalidKey_Throws()
   {
      const string invalid = "not-base64";
      Assert.Throws<ArgumentException>(() => Aes256Siv.Encrypt("x", invalid));
   }

   [Fact]
   public void RegisterKey_Global_Works()
   {
      var key = Key();
      Aes256Siv.RegisterKey(key);
      var c = Aes256Siv.Encrypt("GlobalKey path 🚀");
      var p = Aes256Siv.Decrypt(c);
      Assert.Equal("GlobalKey path 🚀", p);
   }

   [Fact]
   public void ExportImport_Base64_RoundTrip()
   {
      var key = Key();
      var msg = "Payload with ünicode 🌐 and line\r\nbreaks";
      var c = Aes256Siv.Encrypt(msg, key);
      var b64 = Convert.ToBase64String(c);
      var c2 = Convert.FromBase64String(b64);
      var p = Aes256Siv.Decrypt(c2, key);
      Assert.Equal(msg, p);
   }
}