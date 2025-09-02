using Microsoft.AspNetCore.Builder;
using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Extensions;

public static class WebAppExtensions
{
   public static WebApplicationBuilder AddAes256Key(this WebApplicationBuilder builder, string aesKey)
   {
      Aes256.RegisterKey(aesKey);
      Aes256SivLegacy.RegisterKey(aesKey);
      Aes256Gcm.RegisterKey(aesKey);
      Aes256Siv.RegisterKey(aesKey);
      return builder;
   }

   public static WebApplicationBuilder ConfigureArgon2Id(this WebApplicationBuilder builder,
      Action<Argon2IdOptions> configure)
   {
      var options = new Argon2IdOptions();
      configure(options);
      Argon2Id.Configure(options);
      return builder;
   }
}