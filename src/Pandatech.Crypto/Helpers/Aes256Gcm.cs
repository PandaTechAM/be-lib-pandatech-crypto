using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Pandatech.Crypto.Helpers;

public static class Aes256Gcm
{
   private const int KeySize = 32; // 256-bit
   private const int NonceSize = 12; // GCM recommended
   private const int TagSize = 16; // 128-bit tag
   private const int DefaultChunkSize = 64 * 1024;

   // [Magic: 'PGCM'][Version:1][BaseNonce:12][ChunkSize:4 LE]
   // Frames: [PlainLen:4 LE][Tag:16][Ciphertext:PlainLen]
   private static readonly byte[] Magic = "PGCM"u8.ToArray();

   private const byte Version = 1;

   private static string? GlobalKey { get; set; }

   internal static void RegisterKey(string key)
   {
      ValidateKey(key);
      GlobalKey = key;
   }

   public static void Encrypt(Stream input, Stream output) => Encrypt(input, output, null);

   public static void Encrypt(Stream input, Stream output, string? key)
   {
      ArgumentNullException.ThrowIfNull(input);
      ArgumentNullException.ThrowIfNull(output);

      var k = GetKeyBytes(key);

      Span<byte> baseNonce = stackalloc byte[NonceSize];
      RandomNumberGenerator.Fill(baseNonce);

      // header
      Span<byte> header = stackalloc byte[Magic.Length + 1 + NonceSize + 4];
      Magic.CopyTo(header);
      header[4] = Version;
      baseNonce.CopyTo(header.Slice(5, NonceSize));
      BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(5 + NonceSize, 4), (uint)DefaultChunkSize);
      output.Write(header);

      using var aes = new AesGcm(k, TagSize);

      var plain = new byte[DefaultChunkSize];
      var cipher = new byte[DefaultChunkSize]; // <— you removed this; we need it
      var tagBuf = new byte[TagSize];
      var nonceBuf = new byte[NonceSize];
      var frameLen4 = new byte[4];
      var aadLen = 5 + NonceSize + 4;

      ulong counter = 0;
      int read;

      // --- data frames ---
      while ((read = input.Read(plain, 0, plain.Length)) > 0)
      {
         DeriveNonce(baseNonce, counter, nonceBuf);

         var p = plain.AsSpan(0, read);
         var c = cipher.AsSpan(0, read);
         var tag = tagBuf.AsSpan();

         aes.Encrypt(nonceBuf, p, c, tag, header[..aadLen]);

         BinaryPrimitives.WriteUInt32LittleEndian(frameLen4, (uint)read);
         output.Write(frameLen4); // len
         output.Write(tagBuf); // tag
         output.Write(c); // ciphertext

         counter++;
      }

      // --- single terminal 0-length authenticated frame ---
      DeriveNonce(baseNonce, counter, nonceBuf);
      aes.Encrypt(nonceBuf,
         ReadOnlySpan<byte>.Empty,
         Span<byte>.Empty,
         tagBuf,
         header[..aadLen]);

      BinaryPrimitives.WriteUInt32LittleEndian(frameLen4, 0u);
      output.Write(frameLen4);
      output.Write(tagBuf);
   }


   public static void Decrypt(Stream input, Stream output) => Decrypt(input, output, null);

   public static void Decrypt(Stream input, Stream output, string? key)
   {
      ArgumentNullException.ThrowIfNull(input);
      ArgumentNullException.ThrowIfNull(output);

      var k = GetKeyBytes(key);

      // header (single stackalloc outside loops)
      Span<byte> header = stackalloc byte[Magic.Length + 1 + NonceSize + 4];
      ReadExactly(input, header);

      if (!header[..4]
             .SequenceEqual(Magic))
      {
         throw new CryptographicException("Invalid header.");
      }

      if (header[4] != Version)
      {
         throw new CryptographicException("Unsupported version.");
      }

      var baseNonce = header.Slice(5, NonceSize)
                            .ToArray();
      var chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(5 + NonceSize, 4));
      if (chunkSize == 0 || chunkSize > 16 * 1024 * 1024)
         throw new CryptographicException("Invalid chunk size.");

      using var aes = new AesGcm(k, TagSize);

      var cipher = new byte[chunkSize];
      var plain = new byte[chunkSize];
      var tagBuf = new byte[TagSize];
      var nonceBuf = new byte[NonceSize];
      var lenBuf4 = new byte[4];
      var aadLen = 5 + NonceSize + 4;

      ulong counter = 0;
      var sawTerminal = false;

      while (true)
      {
         var got = input.Read(lenBuf4);
         if (got == 0)
            break; // we’ll check sawTerminal below

         if (got != 4)
            throw new CryptographicException("Truncated frame.");

         var len = BinaryPrimitives.ReadUInt32LittleEndian(lenBuf4);
         if (len > chunkSize)
            throw new CryptographicException("Frame too large.");

         ReadExactly(input, tagBuf);

         DeriveNonce(baseNonce, counter, nonceBuf);

         if (len == 0)
         {
            // terminal frame: verify tag on empty payload
            aes.Decrypt(nonceBuf,
               ReadOnlySpan<byte>.Empty,
               tagBuf,
               Span<byte>.Empty,
               header[..aadLen]);

            sawTerminal = true;

            // after terminal, there MUST be no extra data
            if (input.Read(lenBuf4) != 0)
               throw new CryptographicException("Trailing data after terminal frame.");

            break;
         }

         var c = cipher.AsSpan(0, (int)len);
         ReadExactly(input, c);

         var p = plain.AsSpan(0, (int)len);
         aes.Decrypt(nonceBuf, c, tagBuf, p, header[..aadLen]);
         output.Write(p);

         counter++;
      }

      if (!sawTerminal)
         throw new CryptographicException("Missing terminal authentication frame.");
   }

   private static void DeriveNonce(ReadOnlySpan<byte> baseNonce, ulong counter, Span<byte> outNonce)
   {
      // outNonce = baseNonce; then XOR LE64(counter) into last 8 bytes — no temporaries.
      baseNonce.CopyTo(outNonce);
      for (var i = 0; i < 8; i++)
      {
         var b = (byte)((counter >> (8 * i)) & 0xFF);
         outNonce[NonceSize - 8 + i] ^= b;
      }
   }

   private static void ReadExactly(Stream s, Span<byte> buffer)
   {
      var total = 0;
      while (total < buffer.Length)
      {
         var r = s.Read(buffer.Slice(total));
         if (r == 0) throw new CryptographicException("Truncated input.");
         total += r;
      }
   }

   private static byte[] GetKeyBytes(string? overrideKey)
   {
      if (string.IsNullOrEmpty(overrideKey))
      {
         return GlobalKey is null
            ? throw new InvalidOperationException("AES256 Key not configured. Call RegisterKey(...) or provide a key.")
            : Convert.FromBase64String(GlobalKey);
      }

      ValidateKey(overrideKey);
      return Convert.FromBase64String(overrideKey);
   }

   private static void ValidateKey([NotNull] string? key)
   {
      if (string.IsNullOrWhiteSpace(key) || !IsBase64String(key))
      {
         throw new ArgumentException("Key must be valid Base64.");
      }

      if (Convert.FromBase64String(key)
                 .Length != KeySize)
      {
         throw new ArgumentException("Key must be 32 bytes (256 bits).");
      }
   }

   private static bool IsBase64String(string input)
   {
      var buffer = new Span<byte>(new byte[input.Length]);
      return Convert.TryFromBase64String(input, buffer, out _);
   }
}