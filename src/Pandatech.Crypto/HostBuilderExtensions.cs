using Microsoft.Extensions.DependencyInjection;

namespace Pandatech.Crypto;

public static class HostBuilderExtensions
{
    public static IServiceCollection AddPandatechCryptoAes256(this IServiceCollection services, Action<Aes256Options> configure)
    {
        var options = new Aes256Options();
        configure(options);
        ValidateKey(options.Key);
        services.AddSingleton(options);
        services.AddSingleton<Aes256>();
        return services;

    }

    public static IServiceCollection AddPandatechCryptoArgon2Id(this IServiceCollection services, Action<Argon2IdOptions> configure)
    {
        var options = new Argon2IdOptions();
        configure(options);
        services.AddSingleton(options);
        services.AddSingleton<Argon2Id>();
        return services;

    }
    
    private static void ValidateKey(string key)
    {
        if (string.IsNullOrEmpty(key) || !IsBase64String(key) || Convert.FromBase64String(key).Length != 32)
            throw new ArgumentException("Invalid key.");
    }

    public static IServiceCollection AddPandatechCryptoArgon2Id(this IServiceCollection services)
    {
        var options = new Argon2IdOptions();
        services.AddSingleton(options);
        services.AddSingleton<Argon2Id>();
        return services;
    }
    
    private static bool IsBase64String(string s)
    {
        var buffer = new Span<byte>(new byte[s.Length]);
        return Convert.TryFromBase64String(s, buffer, out _);
    }
}