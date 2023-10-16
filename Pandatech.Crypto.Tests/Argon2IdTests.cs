namespace Pandatech.Crypto.Tests;

public class Argon2IdTests
{
    [Fact]
    public void HashVerify_ShouldBeValid()
    {
        var password = RandomPassword.Generate(32, true, true, true, true);
        var hash = Argon2Id.HashPassword(password);

        Assert.True(Argon2Id.VerifyHash(password, hash));
    }
    
    [Fact]
    public void HashVerify_InvalidPassword_ShouldBeInvalid()
    {
        var password = RandomPassword.Generate(32, true, true, true, true);
        var hash = Argon2Id.HashPassword(password);

        
    }
    
    [Fact]
    public void DifferentPasswords_ShouldHaveDifferentHashes()
    {
        var password1 = RandomPassword.Generate(32, true, true, true, true);
        var password2 = RandomPassword.Generate(32, true, true, true, true);
        var hash1 = Argon2Id.HashPassword(password1);
        var hash2 = Argon2Id.HashPassword(password2);

        Assert.NotEqual(hash1, hash2);
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