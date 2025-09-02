using System.Text;
using Pandatech.Crypto.Helpers;
using Random = Pandatech.Crypto.Helpers.Random;
using Xunit;

namespace Pandatech.Crypto.Tests;

public class AesSivMigrationTests
{
   private static string Key() => Random.GenerateAes256KeyString();

   [Fact]
   public void Migrate_Single_RoundTrip_Works()
   {
      var key = Key();
      Aes256SivLegacy.RegisterKey(key);
      Aes256Siv.RegisterKey(key);

      const string original = "John Q. Public / SSN: 123-45-6789";
      var legacy = Aes256SivLegacy.Encrypt(original); // V0

      var migrated = AesSivMigration.Migrate(legacy); // -> V1

      var roundTrip = Aes256Siv.Decrypt(migrated);
      Assert.Equal(original, roundTrip);
   }

   [Fact]
   public void Migrate_Nullable_Single_Null_PassesThrough()
   {
      byte[]? legacy = null;
      var res = AesSivMigration.MigrateNullable(legacy);
      Assert.Null(res);
   }

   [Fact]
   public void Migrate_Batch_NonNullable_Works()
   {
      var key = Key();
      Aes256SivLegacy.RegisterKey(key);
      Aes256Siv.RegisterKey(key);

      var inputs = new[]
      {
         "Alice",
         "Bob",
         "Charlie"
      };
      var legacy = inputs.Select(Aes256SivLegacy.Encrypt)
                         .ToArray();

      var migrated = AesSivMigration.Migrate(legacy);

      var decrypted = migrated.Select(Aes256Siv.Decrypt)
                              .ToArray();
      Assert.Equal(inputs, decrypted);
   }

   [Fact]
   public void Migrate_Batch_Nullable_Mixed_Works()
   {
      var key = Key();
      Aes256SivLegacy.RegisterKey(key);
      Aes256Siv.RegisterKey(key);

      byte[]?[] legacy =
      [
         Aes256SivLegacy.Encrypt("A"),
         null,
         Aes256SivLegacy.Encrypt("C")
      ];

      var migrated = AesSivMigration.MigrateNullable(legacy);

      Assert.NotNull(migrated[0]);
      Assert.Null(migrated[1]);
      Assert.NotNull(migrated[2]);

      var d0 = Aes256Siv.Decrypt(migrated[0]!);
      var d2 = Aes256Siv.Decrypt(migrated[2]!);
      Assert.Equal("A", d0);
      Assert.Equal("C", d2);
   }

   [Fact]
   public void Migrate_TamperedLegacy_Throws()
   {
      var key = Key();
      Aes256SivLegacy.RegisterKey(key);
      Aes256Siv.RegisterKey(key);

      var legacy = Aes256SivLegacy.Encrypt("data");
      legacy[0] ^= 0x01; // corrupt V/tag in legacy payload

      Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
      {
         _ = AesSivMigration.Migrate(legacy);
      });
   }
}