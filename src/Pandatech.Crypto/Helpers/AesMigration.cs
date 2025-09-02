namespace Pandatech.Crypto.Helpers;

[Obsolete("This class is temporary for migration purposes from AES256 to AES256SIV. It will be removed in the future.")]
public static class AesMigration
{
   public static List<byte[]?> MigrateFromOldHashedNullable(IEnumerable<byte[]?> oldCiphertexts)
   {
      return oldCiphertexts.Select(MigrateFromOldHashedNullable)
                           .ToList();
   }

   public static List<byte[]> MigrateFromOldHashed(IEnumerable<byte[]> oldCiphertexts)
   {
      return oldCiphertexts.Select(MigrateFromOldHashed)
                           .ToList();
   }

   public static List<byte[]?> MigrateFromOldNonHashedNullable(IEnumerable<byte[]?> oldCiphertexts)
   {
      return oldCiphertexts.Select(MigrateFromOldNonHashedNullable)
                           .ToList();
   }

   public static List<byte[]> MigrateFromOldNonHashed(IEnumerable<byte[]> oldCiphertexts)
   {
      return oldCiphertexts.Select(MigrateFromOldNonHashed)
                           .ToList();
   }


   public static byte[]? MigrateFromOldHashedNullable(byte[]? oldCiphertext)
   {
      if (oldCiphertext == null)
      {
         return null;
      }

      var plaintext = Aes256.Decrypt(oldCiphertext);

      return Aes256SivLegacy.Encrypt(plaintext);
   }

   public static byte[] MigrateFromOldHashed(byte[] oldCiphertext)
   {
      var plaintext = Aes256.Decrypt(oldCiphertext);

      return Aes256SivLegacy.Encrypt(plaintext);
   }

   public static byte[]? MigrateFromOldNonHashedNullable(byte[]? oldCiphertext)
   {
      if (oldCiphertext == null)
      {
         return null;
      }

      var plaintext = Aes256.DecryptWithoutHash(oldCiphertext);

      return Aes256SivLegacy.Encrypt(plaintext);
   }


   public static byte[] MigrateFromOldNonHashed(byte[] oldCiphertext)
   {
      var plaintext = Aes256.DecryptWithoutHash(oldCiphertext);

      return Aes256SivLegacy.Encrypt(plaintext);
   }
}