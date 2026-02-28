using Microsoft.AspNetCore.Builder;
using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Extensions;

/// <summary>
/// Extension methods for registering Pandatech.Crypto services.
/// </summary>
public static class WebAppExtensions
{
   /// <summary>
   /// Registers a global AES-256 encryption key for all AES helpers (Aes256, Aes256Gcm, Aes256Siv, Aes256SivLegacy).
   /// </summary>
   /// <param name="builder">The web application builder.</param>
   /// <param name="aesKey">Base64-encoded 256-bit (32 bytes) encryption key.</param>
   /// <returns>The web application builder for chaining.</returns>
   /// <exception cref="ArgumentException">Thrown when the key is invalid or not 32 bytes.</exception>
   public static WebApplicationBuilder AddAes256Key(this WebApplicationBuilder builder, string aesKey)
   {
      Aes256.RegisterKey(aesKey);
      Aes256SivLegacy.RegisterKey(aesKey);
      Aes256Gcm.RegisterKey(aesKey);
      Aes256Siv.RegisterKey(aesKey);
      return builder;
   }

   /// <summary>
   /// Configures Argon2id password hashing parameters.
   /// </summary>
   /// <param name="builder">The web application builder.</param>
   /// <param name="configure">Configuration action to set Argon2id options.</param>
   /// <returns>The web application builder for chaining.</returns>
   public static WebApplicationBuilder ConfigureArgon2Id(this WebApplicationBuilder builder,
      Action<Argon2IdOptions> configure)
   {
      var options = new Argon2IdOptions();
      configure(options);
      Argon2Id.Configure(options);
      return builder;
   }
}