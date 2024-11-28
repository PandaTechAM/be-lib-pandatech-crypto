using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Tests;

public class Sha2Tests
{
   [Fact]
   public void HmacSha256_ValidInput_ReturnsExpectedHash()
   {
      // Arrange
      var key = "secret"u8.ToArray();
      var messages = new[]
      {
         "Hello",
         "World"
      };
      const string expectedHashHex = "2e91612bb72b29d82f32789d063de62d5897a4ee5d3b5d34459801b94397b099";

      // Act
      var hashHex = Sha2.GetHmacSha256Hex(key, messages);

      // Assert
      Assert.Equal(expectedHashHex, hashHex);
   }
   
   [Fact]
   public void HmacSha256_ValidInput_ReturnsExpectedHash2()
   {
      // Arrange
      var key = "secret"u8.ToArray();
      var messages = new[]
      {
         "Hello",
         "World"
      };
      const string expectedHashHex = "LpFhK7crKdgvMnidBj3mLViXpO5dO100RZgBuUOXsJk=";

      // Act
      var hashHex = Sha2.GetHmacSha256Base64(key, messages);

      // Assert
      Assert.Equal(expectedHashHex, hashHex);
   }

   [Fact]
   public void HmacSha256_EmptyMessage_ReturnsHash()
   {
      // Arrange
      var key = "secret"u8.ToArray();
      var messages = Array.Empty<string>();

      // Act
      var hash = Sha2.ComputeHmacSha256(key, messages);

      // Assert
      Assert.NotNull(hash);
      Assert.NotEmpty(hash);
   }

   [Fact]
   public void HmacSha256_ConsistentOutput_ForSameInputs()
   {
      // Arrange
      var key = "secret"u8.ToArray();
      var messages = new[]
      {
         "Test",
         "Message"
      };

      // Act
      var hash1 = Sha2.GetHmacSha256Hex(key, messages);
      var hash2 = Sha2.GetHmacSha256Hex(key, messages);

      // Assert
      Assert.Equal(hash1, hash2);
   }

   [Fact]
   public void HmacSha256Base64_ValidInput_ReturnsExpectedBase64()
   {
      // Arrange
      var key = "secret"u8.ToArray();
      var messages = new[]
      {
         "Hello",
         "World"
      };
      const string expectedBase64 = "LpFhK7crKdgvMnidBj3mLViXpO5dO100RZgBuUOXsJk=";

      // Act
      var base64Hash = Sha2.GetHmacSha256Base64(key, messages);

      // Assert
      Assert.Equal(expectedBase64, base64Hash);
   }
}