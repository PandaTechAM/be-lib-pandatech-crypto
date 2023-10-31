using Microsoft.Extensions.DependencyInjection;

namespace Pandatech.Crypto.Tests;

public class HostBuilderTests
{
    [Fact]
    public void AddPandatechCryptoAes256_RegistersServicesCorrectly()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPandatechCryptoAes256(options => 
        {
            options.Key = "abd";
        });

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var aes256Options = serviceProvider.GetRequiredService<Aes256Options>();
        var aes256 = serviceProvider.GetRequiredService<Aes256>();

        Assert.NotNull(aes256Options);
        Assert.Equal("abd", aes256Options.Key);
        Assert.NotNull(aes256);
    }
    [Fact]
    public void AddPandatechCryptoAes256_RegistersAsSingleton()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPandatechCryptoAes256(options => 
        {
            options.Key = "abd";
        });
    
        var serviceProvider = services.BuildServiceProvider();
    
        // Assert
        var aes256Instance1 = serviceProvider.GetRequiredService<Aes256>();
        var aes256Instance2 = serviceProvider.GetRequiredService<Aes256>();
    
        Assert.Same(aes256Instance1, aes256Instance2);
    }
    [Fact]
    public void AddPandatechCryptoArgon2Id_RegistersServicesCorrectly()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPandatechCryptoArgon2Id(options => 
        {
            options.Iterations = 4;
            // ... other configurations
        });

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var argon2IdOptions = serviceProvider.GetRequiredService<Argon2IdOptions>();
        var argon2Id = serviceProvider.GetRequiredService<Argon2Id>();

        Assert.NotNull(argon2IdOptions);
        Assert.Equal(4, argon2IdOptions.Iterations);
        Assert.NotNull(argon2Id);
    }
    [Fact]
    public void AddPandatechCryptoArgon2Id_RegistersAsSingleton()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPandatechCryptoArgon2Id(options => 
        {
            options.Iterations = 4;
            // ... other configurations
        });

        var serviceProvider = services.BuildServiceProvider();
    
        // Assert
        var argon2IdInstance1 = serviceProvider.GetRequiredService<Argon2Id>();
        var argon2IdInstance2 = serviceProvider.GetRequiredService<Argon2Id>();
    
        Assert.Same(argon2IdInstance1, argon2IdInstance2);
    }

}