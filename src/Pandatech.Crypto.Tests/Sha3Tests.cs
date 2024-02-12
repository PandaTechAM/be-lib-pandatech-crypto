using System.Text;

namespace Pandatech.Crypto.Tests;

public class Sha3Tests
{
    [Fact]
    public void Hash_IsNotNull()
    {
        var hash = Sha3.Hash("Hello, world!");
        Assert.NotNull(hash);
    }

    [Fact]
    public void Hash_Length_IsCorrect()
    {
        var hash = Sha3.Hash("Hello, world!");
        Assert.Equal(64, hash.Length); // 512 bits = 64 bytes
    }

    [Fact]
    public void Hash_VerifyHash_IsTrue()
    {
        const string data = "Hello, world!";
        var hash = Sha3.Hash(data);

        var result = Sha3.VerifyHash(data, hash);
        Assert.True(result);
    }
    
    [Fact]
    public void Hash_VerifyHash_WithBytes_IsTrue()
    {
        const string data = "Hello, world!";
        var bytes = Encoding.UTF8.GetBytes(data);
        var hash = Sha3.Hash(bytes);

        var result = Sha3.VerifyHash(data, hash);
        Assert.True(result);
    }

    [Fact]
    public void Hash_VerifyHash_IsFalse()
    {
        var hash = Sha3.Hash("Hello, world!");

        var result = Sha3.VerifyHash("Hello, universe!", hash);
        Assert.False(result);
    }
}