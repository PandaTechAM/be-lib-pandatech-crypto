using Microsoft.AspNetCore.Builder;
using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Extensions;

public static class HostBuilderExtensions
{
   public static WebApplication AddAes256Key(this WebApplication app, string aesKey)
   {
      Aes256.RegisterKey(aesKey);
      return app;
   }

   public static WebApplication ConfigureArgon2Id(this WebApplication app, Action<Argon2IdOptions> configure)
   {
      var options = new Argon2IdOptions();
      configure(options);
      Argon2Id.Configure(options);
      return app;
   }
}