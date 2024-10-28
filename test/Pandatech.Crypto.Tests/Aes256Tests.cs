using System.Text;
using Pandatech.Crypto.Helpers;
using Random = Pandatech.Crypto.Helpers.Random;

namespace Pandatech.Crypto.Tests;

public class Aes256Tests
{
   [Fact]
   public void EncryptDecryptWithHash_ShouldReturnOriginalString()
   {
      var key = Random.GenerateAes256KeyString();
      const string original = "MySensitiveData";
      var encrypted = Aes256.Encrypt(original, key);
      var decrypted = Aes256.Decrypt(encrypted, key);

      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void EncryptDecryptWithoutHash_ShouldReturnOriginalString()
   {
      Aes256.RegisterKey(Random.GenerateAes256KeyString());
      const string original = "MySensitiveData";
      var encrypted = Aes256.EncryptWithoutHash(original);
      var decrypted = Aes256.DecryptWithoutHash(encrypted);

      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void EncryptWithHash_ShouldReturnByteArrayWithHash()
   {
      var key = Random.GenerateAes256KeyString();
      const string original = "MySensitiveData";
      var encryptedWithHash = Aes256.Encrypt(original, key);

      Assert.NotNull(encryptedWithHash);
      Assert.True(encryptedWithHash.Length > original.Length);
      Assert.True(encryptedWithHash.Length > 64);
   }

   [Fact]
   public void EncryptAndHash_ShouldReturnByteArrayWithHash()
   {
      Aes256.RegisterKey(Random.GenerateAes256KeyString());

      const string original = "MySensitiveData";
      var encryptedWithHash = Aes256.Encrypt(original);

      Assert.NotNull(encryptedWithHash);
      Assert.True(encryptedWithHash.Length > original.Length);
      Assert.True(encryptedWithHash.Length > 64);
   }

   [Fact]
   public void DecryptWithParameterAndIgnoringHash_ShouldReturnOriginalString()
   {
      var key = Random.GenerateAes256KeyString();
      const string original = "MySensitiveData";
      var encryptedWithHash = Aes256.Encrypt(original, key);
      var decrypted = Aes256.Decrypt(encryptedWithHash, key);

      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void DecryptWithoutParameterAndIgnoringHash_ShouldReturnOriginalString()
   {
      Aes256.RegisterKey(Random.GenerateAes256KeyString());

      const string original = "MySensitiveData";
      var encryptedWithHash = Aes256.Encrypt(original);
      var decrypted = Aes256.Decrypt(encryptedWithHash);

      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void DecryptIgnoringHashWithInvalidData_ShouldThrowException()
   {
      const string invalidKey = "InvalidKey";
      var invalidData = new byte[50];

      Assert.Throws<ArgumentException>(() => Aes256.Decrypt(invalidData, invalidKey));
   }

   [Fact]
   public void EncryptDecryptWithInvalidKey_ShouldThrowException()
   {
      const string invalidKey = "InvalidKey";
      const string original = "MySensitiveData";

      Assert.Throws<ArgumentException>(() => Aes256.Encrypt(original, invalidKey));
   }

   [Fact]
   public void EncryptDecryptWithShortKey_ShouldThrowException()
   {
      var shortKey = Convert.ToBase64String(new byte[15]); // Less than 256 bits
      const string original = "MySensitiveData";

      Assert.Throws<ArgumentException>(() => Aes256.Encrypt(original, shortKey));
      Assert.Throws<ArgumentException>(() => Aes256.Decrypt([], shortKey));
   }

   [Fact]
   public void EncryptDecryptWithNullCipher_ShouldReturnEmptyString()
   {
      var key = Random.GenerateAes256KeyString();

      Assert.Equal("", Aes256.Decrypt([], key));
   }


   [Fact]
   public void EncryptDecryptStream_ShouldReturnOriginalData()
   {
      // Arrange
      Aes256.RegisterKey(Random.GenerateAes256KeyString());

      const string originalData = "MySensitiveData";
      var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(originalData));
      var outputStream = new MemoryStream();

      // Act
      Aes256.Encrypt(inputStream, outputStream);
      outputStream.Seek(0, SeekOrigin.Begin);

      var resultStream = new MemoryStream();
      Aes256.Decrypt(outputStream, resultStream);
      resultStream.Seek(0, SeekOrigin.Begin);
      var decryptedData = new StreamReader(resultStream).ReadToEnd();

      // Assert
      Assert.Equal(originalData, decryptedData);
   }

   [Fact]
   public void EncryptDecryptStreamWithEmptyContent_ShouldHandleGracefully()
   {
      // Arrange

      var key = Random.GenerateAes256KeyString();
      var inputStream = new MemoryStream();
      var outputStream = new MemoryStream();

      // Act
      Aes256.Encrypt(inputStream, outputStream, key);
      outputStream.Seek(0, SeekOrigin.Begin); // Reset the position for reading.

      var resultStream = new MemoryStream();
      Aes256.Decrypt(outputStream, resultStream, key);
      resultStream.Seek(0, SeekOrigin.Begin);
      var decryptedData = new StreamReader(resultStream).ReadToEnd();

      // Assert
      Assert.Empty(decryptedData);
   }

   [Fact]
   public void EncryptStreamWithInvalidKey_ShouldThrowException()
   {
      // Arrange
      const string invalidKey = "InvalidKey";
      var inputStream = new MemoryStream(Encoding.UTF8.GetBytes("MySensitiveData"));
      var outputStream = new MemoryStream();

      // Act & Assert
      Assert.Throws<ArgumentException>(() => Aes256.Encrypt(inputStream, outputStream, invalidKey));
   }

   [Fact]
   public void DecryptStreamWithInvalidKey_ShouldThrowException()
   {
      // Arrange
      const string invalidKey = "InvalidKey";
      var inputStream = new MemoryStream();
      var outputStream = new MemoryStream();

      // Act & Assert
      Assert.Throws<ArgumentException>(() => Aes256.Decrypt(inputStream, outputStream, invalidKey));
   }
}