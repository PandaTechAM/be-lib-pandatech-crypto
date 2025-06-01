using System.Security.Cryptography;
using System.Text;
using Pandatech.Crypto.Helpers;
using Random = Pandatech.Crypto.Helpers.Random;

namespace Pandatech.Crypto.Tests;

public class Aes256SivTests
{
   private static string GenerateRandomAes256KeyString()
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
   public void EncryptDecrypt_InlineData_WorksForAllKindOfStrings(string original)
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();

      // Act
      var encrypted = Aes256Siv.Encrypt(original, key);
      var decrypted = Aes256Siv.Decrypt(encrypted, key);

      var encryptedBytesToString = Encoding.UTF8.GetString(encrypted);
      // Assert
   
      Assert.NotEqual(original, encryptedBytesToString);
      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void EncryptDecrypt_ReturnsOriginalString()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      const string original = "HelloWorld";

      // Act
      var encrypted = Aes256Siv.Encrypt(original, key);
      var decrypted = Aes256Siv.Decrypt(encrypted, key);


      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void Encrypt_TheSamePlaintextTwice_ProducesSameCiphertext()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      const string original = "DeterministicTest";

      // Act
      var cipher1 = Aes256Siv.Encrypt(original, key);
      var cipher2 = Aes256Siv.Encrypt(original, key);

      // Assert
      Assert.Equal(cipher1, cipher2);
   }

   [Fact]
   public void Encrypt_EmptyPlaintext_ReturnsEmptyCiphertext()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      var emptyPlaintext = Array.Empty<byte>();

      // Act
      var result = Aes256Siv.Encrypt(emptyPlaintext, key);

      // Assert
      Assert.NotNull(result);
      Assert.Empty(result);
   }

   [Fact]
   public void Decrypt_EmptyCiphertext_ReturnsEmptyPlaintext()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      var emptyCiphertext = Array.Empty<byte>();

      // Act
      var result = Aes256Siv.DecryptToBytes(emptyCiphertext, key);

      // Assert
      Assert.NotNull(result);
      Assert.Empty(result);
   }

   [Fact]
   public void Decrypt_CiphertextTooShort_ThrowsArgumentException()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      var invalidCipher = new byte[10]; // Less than 16 bytes

      // Act & Assert
      Assert.Throws<ArgumentException>(() => Aes256Siv.Decrypt(invalidCipher, key));
   }

   [Fact]
   public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      const string original = "SomeData";
      var encrypted = Aes256Siv.Encrypt(original, key);

      // Tamper with 1 byte
      encrypted[5] ^= 0xFF;

      // Act & Assert
      Assert.Throws<CryptographicException>(() => Aes256Siv.Decrypt(encrypted, key));
   }

   [Fact]
   public void EncryptDecrypt_InvalidOverrideKey_ThrowsArgumentException()
   {
      // Arrange
      const string invalidKey = "NotBase64...";
      const string original = "Test123";

      // Act & Assert
      Assert.Throws<ArgumentException>(() => Aes256Siv.Encrypt(original, invalidKey));
   }

   [Fact]
   public void RegisterKey_ThenEncryptDecrypt_WorksCorrectly()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      Aes256Siv.RegisterKey(key);

      const string original = "GlobalKeyIsSetNow";

      // Act
      var encrypted = Aes256Siv.Encrypt(original);
      var decrypted = Aes256Siv.Decrypt(encrypted);

      // Assert
      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void EncryptDecryptStream_RoundTrip_ReturnsOriginalData()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      const string original = "StreamingData";
      using var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(original));
      using var encryptStream = new MemoryStream();
      using var decryptStream = new MemoryStream();

      // Act
      Aes256Siv.Encrypt(inputStream, encryptStream, key);

      // Reset position on the encrypted data
      encryptStream.Seek(0, SeekOrigin.Begin);

      Aes256Siv.Decrypt(encryptStream, decryptStream, key);
      decryptStream.Seek(0, SeekOrigin.Begin);

      var decryptedText = new StreamReader(decryptStream).ReadToEnd();

      // Assert
      Assert.Equal(original, decryptedText);
   }

   [Fact]
   public void EncryptDecryptStream_EmptyContent_ProducesEmptyContent()
   {
      // Arrange
      var key = GenerateRandomAes256KeyString();
      using var emptyInput = new MemoryStream();
      using var encryptStream = new MemoryStream();
      using var decryptStream = new MemoryStream();

      // Act
      Aes256Siv.Encrypt(emptyInput, encryptStream, key);
      encryptStream.Seek(0, SeekOrigin.Begin);

      Aes256Siv.Decrypt(encryptStream, decryptStream, key);
      decryptStream.Seek(0, SeekOrigin.Begin);

      // Assert
      var decryptedText = new StreamReader(decryptStream).ReadToEnd();
      Assert.Empty(decryptedText);
   }

   [Fact]
   public void EncryptStream_InvalidKey_ThrowsArgumentException()
   {
      // Arrange
      const string invalidKey = "NotBase64!";
      var data = new MemoryStream("Some stream data"u8.ToArray());
      var output = new MemoryStream();

      // Act & Assert
      Assert.Throws<ArgumentException>(() => Aes256Siv.Encrypt(data, output, invalidKey));
   }

   [Fact]
   public void DecryptStream_InvalidKey_ThrowsArgumentException()
   {
      // Arrange
      const string invalidKey = "NotBase64!";
      using var input = new MemoryStream([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      using var output = new MemoryStream();

      // Act & Assert
      Assert.Throws<ArgumentException>(() => Aes256Siv.Decrypt(input, output, invalidKey));
   }
   
   [Fact]
   public void ExportImport_Base64Utf8_RoundTrip_Succeeds()
   {
      // Arrange
      var key = Random.GenerateAes256KeyString();
      const string original = "Payload with ünicode 🌐 and line\r\nbreaks";

      // --- export side ----------------------------------------------------
      var cipher        = Aes256Siv.Encrypt(original, key);          // byte[]
      var base64        = Convert.ToBase64String(cipher);            // string
      var fileBytes     = Encoding.UTF8.GetBytes(base64);            // byte[]

      // --- import side ----------------------------------------------------
      var base64FromFile = Encoding.UTF8.GetString(fileBytes);       // string
      var cipherFromFile = Convert.FromBase64String(base64FromFile); // byte[]
      var decrypted      = Aes256Siv.Decrypt(cipherFromFile, key);   // string

      // Assert
      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void ExportImport_RawBinary_RoundTrip_Succeeds()
   {
      // Arrange
      var key = Random.GenerateAes256KeyString();
      const string original = "Binary-only pipeline";

      // --- export side ----------------------------------------------------
      var cipher = Aes256Siv.Encrypt(original, key); // byte[]
      // (write cipher directly to *.pandavault)

      // --- import side ----------------------------------------------------
      var decrypted = Aes256Siv.Decrypt(cipher, key); // byte[]

      // Assert
      Assert.Equal(original, decrypted);
   }

  

}