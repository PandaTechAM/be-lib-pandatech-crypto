using System.Security.Cryptography;
using System.Text;
using Pandatech.Crypto.Helpers;
using Random = Pandatech.Crypto.Helpers.Random;

namespace Pandatech.Crypto.Tests;

public class Aes256GcmTests
{
   private static string Key()
   {
      return Random.GenerateAes256KeyString();
   }

   [Fact]
   public void EncryptDecryptStream_RoundTrip_SmallText()
   {
      var key = Key();
      const string original = "StreamingData-✅-ünicode";
      using var input = new MemoryStream(Encoding.UTF8.GetBytes(original));
      using var enc = new MemoryStream();
      using var dec = new MemoryStream();

      Aes256Gcm.Encrypt(input, enc, key);
      enc.Position = 0;
      Aes256Gcm.Decrypt(enc, dec, key);

      var decrypted = Encoding.UTF8.GetString(dec.ToArray());
      Assert.Equal(original, decrypted);
   }

   [Fact]
   public void EncryptDecryptStream_RoundTrip_LargeBinary_MultiFrame()
   {
      var key = Key();
      var data = new byte[200_000]; // > 3 frames at 64 KiB
      RandomNumberGenerator.Fill(data);

      using var input = new MemoryStream(data);
      using var enc = new MemoryStream();
      using var dec = new MemoryStream();

      Aes256Gcm.Encrypt(input, enc, key);
      enc.Position = 0;
      Aes256Gcm.Decrypt(enc, dec, key);

      Assert.Equal(data, dec.ToArray());
   }

   [Fact]
   public void EncryptDecryptStream_EmptyContent_ProducesEmpty()
   {
      var key = Key();
      using var input = new MemoryStream();
      using var enc = new MemoryStream();
      using var dec = new MemoryStream();

      Aes256Gcm.Encrypt(input, enc, key);
      enc.Position = 0;
      Aes256Gcm.Decrypt(enc, dec, key);

      Assert.Equal(0, dec.Length);
   }

   [Fact]
   public void EncryptStream_InvalidKey_ThrowsArgumentException()
   {
      const string invalidKey = "NotBase64!";
      using var input = new MemoryStream("data"u8.ToArray());
      using var enc = new MemoryStream();
      Assert.Throws<ArgumentException>(() => Aes256Gcm.Encrypt(input, enc, invalidKey));
   }

   [Fact]
   public void DecryptStream_InvalidKey_ThrowsArgumentException()
   {
      const string invalidKey = "NotBase64!";
      // minimal valid header so we don't hit truncation first
      using var enc = new MemoryStream();
      // Write: 'PGCM' + version + baseNonce(12) + chunkSize(4)
      enc.Write("PGCM"u8);
      enc.WriteByte(1);
      enc.Write(new byte[12]);
      enc.Write(BitConverter.GetBytes(64 * 1024));
      enc.Position = 0;

      using var dec = new MemoryStream();
      Assert.Throws<ArgumentException>(() => Aes256Gcm.Decrypt(enc, dec, invalidKey));
   }

   [Fact]
   public void Decrypt_TamperedHeader_ThrowsCryptographicException()
   {
      var key = Key();
      using var input = new MemoryStream("hello"u8.ToArray());
      using var enc = new MemoryStream();
      Aes256Gcm.Encrypt(input, enc, key);

      var buf = enc.ToArray();
      buf[0] ^= 0xFF; // corrupt magic
      using var tampered = new MemoryStream(buf);
      using var dec = new MemoryStream();

      Assert.Throws<CryptographicException>(() => Aes256Gcm.Decrypt(tampered, dec, key));
   }

   [Fact]
   public void Decrypt_TamperedTag_ThrowsCryptographicException()
   {
      var key = Key();
      using var input = new MemoryStream(new byte[100]);
      using var enc = new MemoryStream();
      Aes256Gcm.Encrypt(input, enc, key);

      var bytes = enc.ToArray();
      var headerLen = 4 + 1 + 12 + 4; // PGCM + ver + baseNonce + chunkSize
      var len = BitConverter.ToInt32(bytes, headerLen);
      var tagPos = headerLen + 4;
      bytes[tagPos] ^= 0x01; // flip 1 bit in tag

      using var tampered = new MemoryStream(bytes);
      using var dec = new MemoryStream();

      Assert.ThrowsAny<CryptographicException>(() => Aes256Gcm.Decrypt(tampered, dec, key));
   }

   [Fact]
   public void RegisterKey_ThenEncryptDecrypt_Works()
   {
      var key = Key();
      Aes256Gcm.RegisterKey(key);

      var data = "GlobalKey path 🚀"u8.ToArray();
      using var input = new MemoryStream(data);
      using var enc = new MemoryStream();
      using var dec = new MemoryStream();

      Aes256Gcm.Encrypt(input, enc);
      enc.Position = 0;
      Aes256Gcm.Decrypt(enc, dec);

      Assert.Equal(data, dec.ToArray());
   }

   [Fact]
   public void ExportImport_Base64_RoundTrip_Succeeds()
   {
      var key = Key();
      var data = "Payload with ünicode 🌐 and line\r\nbreaks"u8.ToArray();
      using var input = new MemoryStream(data);
      using var enc = new MemoryStream();

      Aes256Gcm.Encrypt(input, enc, key);
      var cipherBytes = enc.ToArray();
      var b64 = Convert.ToBase64String(cipherBytes);
      var restored = Convert.FromBase64String(b64);

      using var enc2 = new MemoryStream(restored);
      using var dec = new MemoryStream();
      Aes256Gcm.Decrypt(enc2, dec, key);

      Assert.Equal(data, dec.ToArray());
   }
}