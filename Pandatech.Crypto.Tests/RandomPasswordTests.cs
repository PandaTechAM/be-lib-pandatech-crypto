namespace Pandatech.Crypto.Tests;

public class RandomPasswordTests
{
    [Theory]
    [InlineData(7, true, true, true, true)]
    [InlineData(4, false, true, false, false)]
    [InlineData(5, true, true, true, false)]
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
}