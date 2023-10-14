namespace Pandatech.Crypto.Tests;

public class UnitTests
{
    [Fact]
    public void Generate_ShouldReturnByteArray()
    {
        const int length = 16;
        var randomBytes = Random.GenerateBytes(length);

        Assert.NotNull(randomBytes);
        Assert.Equal(length, randomBytes.Length);
    }

    [Theory]
    [InlineData(100, true, true, true, true)]
    [InlineData(10, false, true, false, false)]
    [InlineData(50, true, true, true, false)]
    public void Generate_ShouldReturnPasswordWithCorrectProperties(
        int length,
        bool includeUppercase,
        bool includeLowercase,
        bool includeDigits,
        bool includeSpecialChars)
    {
        // Generate a random password
        var password = RandomPassword.Generate(length, includeUppercase, includeLowercase, includeDigits,
            includeSpecialChars);

        // Check if the password length is correct
        Assert.Equal(length, password.Length);

        // Check if the password contains the correct character sets
        if (includeUppercase)
            Assert.Contains(password, char.IsUpper);
        if (includeLowercase)
            Assert.Contains(password, char.IsLower);
        if (includeDigits)
            Assert.Contains(password, char.IsDigit);
        if (includeSpecialChars)
            Assert.Contains(password, c => "!@#$%^&*()-_=+[]{}|;:'\",.<>?".Contains(c));
    }

    [Fact]
    public void Generate_ShouldReturnDifferentPasswords()
    {
        var password1 = RandomPassword.Generate(12, true, true, true, true);
        var password2 = RandomPassword.Generate(12, true, true, true, true);

        Assert.NotEqual(password1, password2);
    }

    [Fact]
    public void HashVerify_ShouldBeValid()
    {
        var password = RandomPassword.Generate(32, true, true, true, true);
        var hash = Argon2Id.HashPassword(password);

        Assert.True(Argon2Id.VerifyHash(password, hash));
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
    public void HashPassword_EmptyPassword_ShouldThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2Id.HashPassword(""));
    }

    [Fact]
    public void VerifyHash_NullHash_ShouldThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2Id.VerifyHash("password", null!));
    }
}