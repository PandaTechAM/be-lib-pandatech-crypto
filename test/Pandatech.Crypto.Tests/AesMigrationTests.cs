using Pandatech.Crypto.Helpers;
using Random = Pandatech.Crypto.Helpers.Random;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Pandatech.Crypto.Tests;

public class AesMigrationTests
{
   public AesMigrationTests()
   {
      var key = Random.GenerateAes256KeyString();
      Aes256.RegisterKey(key);
      Aes256Siv.RegisterKey(key);
   }

   [Fact]
   public void MigrateFromOldHashed_SingleItem_RoundTrip()
   {
      const string originalText = "Hello Hashed World";
      // Old encryption (with hash)
      var oldCiphertext = Aes256.Encrypt(originalText);

      // Migrate (decrypt old => encrypt new)
      var newCiphertext = AesMigration.MigrateFromOldHashed(oldCiphertext);

      // Decrypt new ciphertext with SIV
      var decrypted = Aes256Siv.Decrypt(newCiphertext);
      Assert.Equal(originalText, decrypted);
   }

   [Fact]
   public void MigrateFromOldNonHashed_SingleItem_RoundTrip()
   {
      const string originalText = "Hello Non-Hashed World";
      // Old encryption (without hash)
      var oldCiphertext = Aes256.EncryptWithoutHash(originalText);

      // Migrate
      var newCiphertext = AesMigration.MigrateFromOldNonHashed(oldCiphertext);

      // Decrypt new ciphertext with SIV
      var decrypted = Aes256Siv.Decrypt(newCiphertext);
      Assert.Equal(originalText, decrypted);
   }

   [Fact]
   public void MigrateFromOldHashedNullable_NullInput_ReturnsNull()
   {
      byte[]? nullInput = null;
      var result = AesMigration.MigrateFromOldHashedNullable(nullInput);
      Assert.Null(result);
   }

   [Fact]
   public void MigrateFromOldNonHashedNullable_NullInput_ReturnsNull()
   {
      byte[]? nullInput = null;
      var result = AesMigration.MigrateFromOldNonHashedNullable(nullInput);
      Assert.Null(result);
   }

   [Fact]
   public void MigrateFromOldHashed_Collection_RoundTrip()
   {
      var plaintexts = new[]
      {
         "One",
         "Two",
         "Three"
      };
      var oldCipherList = plaintexts
                          .Select(Aes256.Encrypt) // Old hashed
                          .ToList();

      var newCipherList = AesMigration.MigrateFromOldHashed(oldCipherList);

      var decryptedList = newCipherList
                          .Select(nc => Aes256Siv.Decrypt(nc))
                          .ToArray();

      for (var i = 0; i < plaintexts.Length; i++)
      {
         Assert.Equal(plaintexts[i], decryptedList[i]);
      }
   }

   [Fact]
   public void MigrateFromOldNonHashed_Collection_RoundTrip()
   {
      var plaintexts = new[]
      {
         "Alpha",
         "Beta",
         "Gamma"
      };
      var oldCipherList = plaintexts
                          .Select(Aes256.EncryptWithoutHash) // Old non-hashed
                          .ToList();

      var newCipherList = AesMigration.MigrateFromOldNonHashed(oldCipherList);

      var decryptedList = newCipherList
                          .Select(nc => Aes256Siv.Decrypt(nc))
                          .ToArray();

      Assert.Equal(plaintexts, decryptedList);
   }

   [Fact]
   public void MigrateFromOldHashedNullable_CollectionWithNulls_RoundTrip()
   {
      var plaintexts = new[]
      {
         "First",
         null,
         "Second"
      };
      // Old hashed ciphertext plus a null
      var oldCipherList = plaintexts
                          .Select(pt => pt == null ? null : Aes256.Encrypt(pt))
                          .ToList();

      var newCipherList = AesMigration.MigrateFromOldHashedNullable(oldCipherList);

      var decryptedList = newCipherList
                          .Select(nc => nc == null ? null : Aes256Siv.Decrypt(nc))
                          .ToArray();

      Assert.Equal(plaintexts, decryptedList);
   }

   [Fact]
   public void MigrateFromOldNonHashedNullable_CollectionWithNulls_RoundTrip()
   {
      var plaintexts = new[]
      {
         "X",
         null,
         "Y"
      };
      var oldCipherList = plaintexts
                          .Select(pt => pt == null ? null : Aes256.EncryptWithoutHash(pt))
                          .ToList();

      var newCipherList = AesMigration.MigrateFromOldNonHashedNullable(oldCipherList);

      var decryptedList = newCipherList
                          .Select(nc => nc == null ? null : Aes256Siv.Decrypt(nc))
                          .ToArray();

      Assert.Equal(plaintexts, decryptedList);
   }
}