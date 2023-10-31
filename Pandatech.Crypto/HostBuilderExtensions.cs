using Microsoft.Extensions.DependencyInjection;

namespace Pandatech.Crypto;

public static class HostBuilderExtensions
{
    public static void AddPandatechCryptoAes256(this IServiceCollection services, Action<Aes256Options> configure)
    {
        var options = new Aes256Options();
        configure(options);
        services.AddSingleton(options);
        services.AddSingleton<Aes256>();
    }
    
    public static void AddPandatechCryptoArgon2Id(this IServiceCollection services, Action<Argon2IdOptions> configure)
    {
        var options = new Argon2IdOptions();
        configure(options);
        services.AddSingleton(options);
        services.AddSingleton<Argon2Id>();
    }
}