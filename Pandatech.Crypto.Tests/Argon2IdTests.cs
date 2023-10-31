namespace Pandatech.Crypto.Tests;

public class Argon2IdTests
{
    [Fact]
    public void HashVerify_ShouldFailForDifferentArgonConfigs()
    {
        var argon2Id = new Argon2Id();
        var argon2Id2 = new Argon2Id(new Argon2IdOptions { SaltSize = 16, MemorySize = 128, DegreeOfParallelism = 1, Iterations = 1 });
        var password = RandomPassword.Generate(32, true, true, true, true);
        var hash = argon2Id.HashPassword(password);
        Assert.False(argon2Id2.VerifyHash(password, hash));
    }

    [Fact]
    public void HashVerify_ShouldBeValid()
    {
        var argon2Id = new Argon2Id();

        var password = RandomPassword.Generate(32, true, true, true, true);
        var hash = argon2Id.HashPassword(password);

        Assert.True(argon2Id.VerifyHash(password, hash));
    }

    [Fact]
    public void HashVerify_InvalidPassword_ShouldBeInvalid()
    {
        var argon2Id = new Argon2Id();
        var password = RandomPassword.Generate(32, true, true, true, true);
        var hash = argon2Id.HashPassword(password);
        Assert.False(argon2Id.VerifyHash("SomePassword", hash));
    }

    [Fact]
    public void DifferentPasswords_ShouldHaveDifferentHashes()
    {
        var argon2Id = new Argon2Id();
        var password1 = RandomPassword.Generate(32, true, true, true, true);
        var password2 = RandomPassword.Generate(32, true, true, true, true);
        var hash1 = argon2Id.HashPassword(password1);
        var hash2 = argon2Id.HashPassword(password2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void HashPassword_EmptyPassword_ShouldThrowException()
    {
        var argon2Id = new Argon2Id();
        Assert.Throws<ArgumentException>(() => argon2Id.HashPassword(""));
    }

    [Fact]
    public void VerifyHash_NullHash_ShouldThrowException()
    {
        var argon2Id = new Argon2Id();
        Assert.Throws<ArgumentException>(() => argon2Id.VerifyHash("password", null!));
    }
}