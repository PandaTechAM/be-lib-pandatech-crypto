namespace Pandatech.Crypto.Helpers;

[Obsolete("Temporary helper to migrate from Aes256SivLegacy to Aes256Siv. Remove after backfill.")]
public static class AesSivMigration
{
   // -------------------- batch (nullable) --------------------
   public static List<byte[]?> MigrateNullable(IEnumerable<byte[]?> oldCiphertexts) =>
      oldCiphertexts.Select(MigrateNullable)
                    .ToList();

   // -------------------- batch (non-nullable) ----------------
   public static List<byte[]> Migrate(IEnumerable<byte[]> oldCiphertexts) =>
      oldCiphertexts.Select(Migrate)
                    .ToList();

   // -------------------- single (nullable) -------------------
   public static byte[]? MigrateNullable(byte[]? oldCiphertext)
   {
      if (oldCiphertext is null) return null;

      // decrypt with legacy (string API) -> re-encrypt with RFC-correct Aes256Siv
      var plaintext = Aes256SivLegacy.Decrypt(oldCiphertext);
      return Aes256Siv.Encrypt(plaintext);
   }

   // -------------------- single (non-nullable) ---------------
   public static byte[] Migrate(byte[] oldCiphertext)
   {
      var plaintext = Aes256SivLegacy.Decrypt(oldCiphertext);
      return Aes256Siv.Encrypt(plaintext);
   }
}