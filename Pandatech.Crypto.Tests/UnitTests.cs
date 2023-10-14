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
    [InlineData(25, true, true, true, true)]
    [InlineData(25, false, true, false, false)]
    [InlineData(25, true, true, true, false)]
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
}