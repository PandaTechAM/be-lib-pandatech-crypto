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
        var aes256 = new Aes256(new Aes256Options());

        var key = Random.GenerateAes256KeyString();
        const string original = "MySensitiveData";
        var encrypted = aes256.Encrypt(original, key);
        var decrypted = aes256.Decrypt(encrypted, key);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptWithoutParameter_ShouldReturnOriginalString()
    {
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());
        const string original = "MySensitiveData";
        var encrypted = aes256.Encrypt(original);
        var decrypted = aes256.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptWithParameterAndHash_ShouldReturnByteArrayWithHash()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();
        const string original = "MySensitiveData";
        var encryptedWithHash = aes256.EncryptWithHash(original, key);

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
        var encryptedWithHash = aes256.EncryptWithHash(original);

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
        var encryptedWithHash = aes256.EncryptWithHash(original, key);
        var decrypted = aes256.DecryptIgnoringHash(encryptedWithHash, key);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void DecryptWithoutParameterAndIgnoringHash_ShouldReturnOriginalString()
    {
        var aes256Options = new Aes256Options { Key = Random.GenerateAes256KeyString() };
        var aes256 = new Aes256(aes256Options);
        Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());
        const string original = "MySensitiveData";
        var encryptedWithHash = aes256.EncryptWithHash(original);
        var decrypted = aes256.DecryptIgnoringHash(encryptedWithHash);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void DecryptIgnoringHashWithInvalidData_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        const string invalidKey = "InvalidKey";
        var invalidData = new byte[50];

        Assert.Throws<ArgumentException>(() => aes256.DecryptIgnoringHash(invalidData, invalidKey));
    }

    [Fact]
    public void EncryptDecryptWithInvalidKey_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        const string invalidKey = "InvalidKey";
        const string original = "MySensitiveData";

        Assert.Throws<ArgumentException>(() => aes256.Encrypt(original, invalidKey));
        Assert.Throws<ArgumentException>(() => aes256.Decrypt(Array.Empty<byte>(), invalidKey));
    }

    [Fact]
    public void EncryptDecryptWithShortKey_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        var shortKey = Convert.ToBase64String(new byte[15]); // Less than 256 bits
        const string original = "MySensitiveData";

        Assert.Throws<ArgumentException>(() => aes256.Encrypt(original, shortKey));
        Assert.Throws<ArgumentException>(() => aes256.Decrypt(Array.Empty<byte>(), shortKey));
    }

    [Fact]
    public void EncryptDecryptWithEmptyText_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();
        var original = string.Empty;

        Assert.Throws<ArgumentException>(() => aes256.Encrypt(original, key));
        Assert.Throws<ArgumentException>(() => aes256.Decrypt(Array.Empty<byte>(), key));
    }

    [Fact]
    public void EncryptDecryptWithNullCipher_ShouldThrowException()
    {
        var aes256 = new Aes256(new Aes256Options());
        var key = Random.GenerateAes256KeyString();

        Assert.Throws<ArgumentException>(() => aes256.Decrypt(null!, key));
    }
}