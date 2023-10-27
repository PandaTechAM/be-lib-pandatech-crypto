namespace Pandatech.Crypto.Tests;

public class Aes256Tests
{
    [Fact]
    public void Generate_ShouldReturnByteArray()
    {
        const int length = 16;
        var randomBytes = Random.GenerateBytes(length);

        Assert.NotNull(randomBytes);
        Assert.Equal(length, randomBytes.Length);
    }

    

    [Fact]
    public void EncryptDecryptWithParameter_ShouldReturnOriginalString()
    {
        var key = Random.GenerateAes256KeyString();
        const string original = "MySensitiveData";
        var encrypted = Aes256.Encrypt(original, key);
        var decrypted = Aes256.Decrypt(encrypted, key);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptWithoutParameter_ShouldReturnOriginalString()
    {
        Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());
        const string original = "MySensitiveData";
        var encrypted = Aes256.Encrypt(original);
        var decrypted = Aes256.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptWithInvalidKey_ShouldThrowException()
    {
        const string invalidKey = "InvalidKey";
        const string original = "MySensitiveData";

        Assert.Throws<ArgumentException>(() => Aes256.Encrypt(original, invalidKey));
        Assert.Throws<ArgumentException>(() => Aes256.Decrypt(Array.Empty<byte>(), invalidKey));
    }

    [Fact]
    public void EncryptDecryptWithShortKey_ShouldThrowException()
    {
        var shortKey = Convert.ToBase64String(new byte[15]); // Less than 256 bits
        const string original = "MySensitiveData";

        Assert.Throws<ArgumentException>(() => Aes256.Encrypt(original, shortKey));
        Assert.Throws<ArgumentException>(() => Aes256.Decrypt(Array.Empty<byte>(), shortKey));
    }

    [Fact]
    public void EncryptDecryptWithEmptyText_ShouldThrowException()
    {
        var key = Random.GenerateAes256KeyString();
        var original = string.Empty;

        Assert.Throws<ArgumentException>(() => Aes256.Encrypt(original, key));
        Assert.Throws<ArgumentException>(() => Aes256.Decrypt(Array.Empty<byte>(), key));
    }

    [Fact]
    public void EncryptDecryptWithNullCipher_ShouldThrowException()
    {
        var key = Random.GenerateAes256KeyString();

        Assert.Throws<ArgumentException>(() => Aes256.Decrypt(null!, key));
    }
    
     [Fact]
        public void EncryptWithHash_ShouldReturnByteArrayWithHash()
        {
            var key = Random.GenerateAes256KeyString();
            const string original = "MySensitiveData";
            var encryptedWithHash = Aes256.EncryptWithHash(original, key);
            
            Assert.NotNull(encryptedWithHash);
            Assert.True(encryptedWithHash.Length > original.Length);
            Assert.True(encryptedWithHash.Length > 64);
        }

        [Fact]
        public void DecryptIgnoringHash_ShouldReturnOriginalString()
        {
            var key = Random.GenerateAes256KeyString();
            const string original = "MySensitiveData";
            var encryptedWithHash = Aes256.EncryptWithHash(original, key);
            var decrypted = Aes256.DecryptIgnoringHash(encryptedWithHash, key);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void DecryptIgnoringHashWithInvalidData_ShouldThrowException()
        {
            const string invalidKey = "InvalidKey";
            var invalidData = new byte[50];

            Assert.Throws<ArgumentException>(() => Aes256.DecryptIgnoringHash(invalidData, invalidKey));
        }
        

    
}