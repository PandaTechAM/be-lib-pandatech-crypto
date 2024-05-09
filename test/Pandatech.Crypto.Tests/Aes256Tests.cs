using System.Text;

namespace Pandatech.Crypto.Tests;

public class Aes256Tests
{
    [Fact]
    public void EncryptDecryptWithParameter_ShouldReturnOriginalString()
    {
        var aes256 = new Aes256(new Aes256Options());

        var key = Random.GenerateAes256KeyString();
        const string original = "MySensitiveData";
        var encrypted = aes256.Encrypt(original, key, false);
        var decrypted = aes256.Decrypt(encrypted, key, false);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptWithoutParameter_ShouldReturnOriginalString()
    {
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());
        const string original = "MySensitiveData";
        var encrypted = aes256.Encrypt(original, false);
        var decrypted = aes256.Decrypt(encrypted, false);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptWithParameterAndHash_ShouldReturnByteArrayWithHash()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();
        const string original = "MySensitiveData";
        var encryptedWithHash = aes256.Encrypt(original, key);

        Assert.NotNull(encryptedWithHash);
        Assert.True(encryptedWithHash.Length > original.Length);
        Assert.True(encryptedWithHash.Length > 64);
    }

    [Fact]
    public void EncryptWithoutParameterAndHash_ShouldReturnByteArrayWithHash()
    {
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());
        const string original = "MySensitiveData";
        var encryptedWithHash = aes256.Encrypt(original);

        Assert.NotNull(encryptedWithHash);
        Assert.True(encryptedWithHash.Length > original.Length);
        Assert.True(encryptedWithHash.Length > 64);
    }

    [Fact]
    public void DecryptWithParameterAndIgnoringHash_ShouldReturnOriginalString()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();
        const string original = "MySensitiveData";
        var encryptedWithHash = aes256.Encrypt(original, key);
        var decrypted = aes256.Decrypt(encryptedWithHash, key);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void DecryptWithoutParameterAndIgnoringHash_ShouldReturnOriginalString()
    {
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());
        const string original = "MySensitiveData";
        var encryptedWithHash = aes256.Encrypt(original);
        var decrypted = aes256.Decrypt(encryptedWithHash);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void DecryptIgnoringHashWithInvalidData_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        const string invalidKey = "InvalidKey";
        var invalidData = new byte[50];

        Assert.Throws<ArgumentException>(() => aes256.Decrypt(invalidData, invalidKey));
    }

    [Fact]
    public void EncryptDecryptWithInvalidKey_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        const string invalidKey = "InvalidKey";
        const string original = "MySensitiveData";

        Assert.Throws<ArgumentException>(() => aes256.Encrypt(original, invalidKey));
    }

    [Fact]
    public void EncryptDecryptWithShortKey_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        var shortKey = Convert.ToBase64String(new byte[15]); // Less than 256 bits
        const string original = "MySensitiveData";

        Assert.Throws<ArgumentException>(() => aes256.Encrypt(original, shortKey));
        Assert.Throws<ArgumentException>(() => aes256.Decrypt([], shortKey));
    }

    [Fact]
    public void EncryptDecryptWithEmptyText_ShouldReturnEmptyString()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();
        var original = string.Empty;
        var encrypted = aes256.Encrypt(original, key);
        var decrypted = aes256.Decrypt(encrypted, key);
        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptWithNullCipher_ShouldReturnEmptyString()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();

        Assert.Equal("", aes256.Decrypt([], key));
    }

    [Fact]
    public void GenerateAes256KeyIsValidInLoop()
    {
        for (var i = 0; i < 1_000; i++)
        {
            var aes256 = new Aes256(new Aes256Options()
            {
                Key = Random.GenerateAes256KeyString()
            });
            var encrypt = aes256.Encrypt("MySensitiveData");
            var decrypt = aes256.Decrypt(encrypt);
            Assert.Equal("MySensitiveData", decrypt);
        }
    }

    [Fact]
    public void EncryptDecryptStream_ShouldReturnOriginalData()
    {
        // Arrange
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        const string originalData = "MySensitiveData";
        var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(originalData));
        var outputStream = new MemoryStream();

        // Act
        aes256.EncryptStream(inputStream, outputStream, aes256Options.Key);
        outputStream.Seek(0, SeekOrigin.Begin);

        var resultStream = new MemoryStream();
        aes256.DecryptStream(outputStream, resultStream, aes256Options.Key);
        resultStream.Seek(0, SeekOrigin.Begin);
        var decryptedData = new StreamReader(resultStream).ReadToEnd();

        // Assert
        Assert.Equal(originalData, decryptedData);
    }

    [Fact]
    public void EncryptDecryptStreamWithEmptyContent_ShouldHandleGracefully()
    {
        // Arrange
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        var inputStream = new MemoryStream();
        var outputStream = new MemoryStream();

        // Act
        aes256.EncryptStream(inputStream, outputStream, aes256Options.Key);
        outputStream.Seek(0, SeekOrigin.Begin); // Reset the position for reading.

        var resultStream = new MemoryStream();
        aes256.DecryptStream(outputStream, resultStream, aes256Options.Key);
        resultStream.Seek(0, SeekOrigin.Begin);
        var decryptedData = new StreamReader(resultStream).ReadToEnd();

        // Assert
        Assert.Empty(decryptedData);
    }

    [Fact]
    public void EncryptStreamWithInvalidKey_ShouldThrowException()
    {
        // Arrange
        var aes256 = new Aes256(new Aes256Options());
        const string invalidKey = "InvalidKey";
        var inputStream = new MemoryStream(Encoding.UTF8.GetBytes("MySensitiveData"));
        var outputStream = new MemoryStream();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => aes256.EncryptStream(inputStream, outputStream, invalidKey));
    }

    [Fact]
    public void DecryptStreamWithInvalidKey_ShouldThrowException()
    {
        // Arrange
        var aes256 = new Aes256(new Aes256Options());
        const string invalidKey = "InvalidKey";
        var inputStream = new MemoryStream();
        var outputStream = new MemoryStream();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => aes256.DecryptStream(inputStream, outputStream, invalidKey));
    }
}