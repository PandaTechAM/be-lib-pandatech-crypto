using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Pandatech.Crypto.Helpers;

/// <summary>
/// AES-256-GCM authenticated encryption for streams with chunked framing.
/// Perfect for files: images, videos, PDFs, etc.
/// </summary>
public static class Aes256Gcm
{
   private const int KeySize = 32; // 256-bit
   private const int NonceSize = 12; // GCM recommended
   private const int TagSize = 16; // 128-bit tag
   private const int DefaultChunkSize = 64 * 1024; // 64 KiB

   private const byte Version = 1;

   // [Magic: 'PGCM'][Version:1][BaseNonce:12][ChunkSize:4 LE]
   // Frames: [PlainLen:4 LE][Tag:16][Ciphertext:PlainLen]
   private static readonly byte[] Magic = "PGCM"u8.ToArray();

   private static string? GlobalKey { get; set; }

   /// <summary>
   /// Register a global AES-256 key (base64-encoded, 32 bytes).
   /// </summary>
   internal static void RegisterKey(string key)
   {
      ValidateKey(key);
      GlobalKey = key;
   }

   /// <summary>
   /// Encrypt a stream using AES-256-GCM with the registered global key.
   /// </summary>
   public static void Encrypt(Stream input, Stream output)
   {
      Encrypt(input, output, null);
   }

   /// <summary>
   /// Encrypt a stream using AES-256-GCM with an optional override key.
   /// </summary>
   public static void Encrypt(Stream input, Stream output, string? key)
   {
      ArgumentNullException.ThrowIfNull(input);
      ArgumentNullException.ThrowIfNull(output);

      var k = GetKeyBytes(key);

      Span<byte> baseNonce = stackalloc byte[NonceSize];
      RandomNumberGenerator.Fill(baseNonce);

      // Write header
      Span<byte> header = stackalloc byte[Magic.Length + 1 + NonceSize + 4];
      Magic.CopyTo(header);
      header[4] = Version;
      baseNonce.CopyTo(header.Slice(5, NonceSize));
      BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(5 + NonceSize, 4), DefaultChunkSize);
      output.Write(header);

      using var aes = new AesGcm(k, TagSize);

      // Rent buffers from pool to reduce allocations
      var plainBuffer = ArrayPool<byte>.Shared.Rent(DefaultChunkSize);
      var cipherBuffer = ArrayPool<byte>.Shared.Rent(DefaultChunkSize);
      
      try
      {
         var tagBuf = new byte[TagSize];
         var nonceBuf = new byte[NonceSize];
         var frameLen4 = new byte[4];
         var aadLen = 5 + NonceSize + 4;

         ulong counter = 0;
         int read;

         // Data frames
         while ((read = input.Read(plainBuffer, 0, DefaultChunkSize)) > 0)
         {
            DeriveNonce(baseNonce, counter, nonceBuf);

            var p = plainBuffer.AsSpan(0, read);
            var c = cipherBuffer.AsSpan(0, read);

            aes.Encrypt(nonceBuf, p, c, tagBuf, header[..aadLen]);

            BinaryPrimitives.WriteUInt32LittleEndian(frameLen4, (uint)read);
            output.Write(frameLen4);
            output.Write(tagBuf);
            output.Write(c);

            counter++;
         }

         // Terminal 0-length authenticated frame
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
      finally
      {
         ArrayPool<byte>.Shared.Return(plainBuffer);
         ArrayPool<byte>.Shared.Return(cipherBuffer);
      }
   }

   /// <summary>
   /// Decrypt a stream using AES-256-GCM with the registered global key.
   /// </summary>
   public static void Decrypt(Stream input, Stream output)
   {
      Decrypt(input, output, null);
   }

   /// <summary>
   /// Decrypt a stream using AES-256-GCM with an optional override key.
   /// </summary>
   public static void Decrypt(Stream input, Stream output, string? key)
   {
      ArgumentNullException.ThrowIfNull(input);
      ArgumentNullException.ThrowIfNull(output);

      var k = GetKeyBytes(key);

      // Read and validate header
      Span<byte> header = stackalloc byte[Magic.Length + 1 + NonceSize + 4];
      ReadExactly(input, header);

      if (!header[..4].SequenceEqual(Magic))
      {
         throw new CryptographicException("Invalid header.");
      }

      if (header[4] != Version)
      {
         throw new CryptographicException("Unsupported version.");
      }

      var baseNonce = header.Slice(5, NonceSize).ToArray();
      var chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(5 + NonceSize, 4));
      
      if (chunkSize == 0 || chunkSize > 16 * 1024 * 1024)
      {
         throw new CryptographicException("Invalid chunk size.");
      }

      using var aes = new AesGcm(k, TagSize);

      // Rent buffers from pool
      var cipherBuffer = ArrayPool<byte>.Shared.Rent((int)chunkSize);
      var plainBuffer = ArrayPool<byte>.Shared.Rent((int)chunkSize);
      
      try
      {
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
            {
               break;
            }

            if (got != 4)
            {
               throw new CryptographicException("Truncated frame.");
            }

            var len = BinaryPrimitives.ReadUInt32LittleEndian(lenBuf4);
            if (len > chunkSize)
            {
               throw new CryptographicException("Frame too large.");
            }

            ReadExactly(input, tagBuf);
            DeriveNonce(baseNonce, counter, nonceBuf);

            if (len == 0)
            {
               // Terminal frame: verify tag on empty payload
               aes.Decrypt(nonceBuf,
                  ReadOnlySpan<byte>.Empty,
                  tagBuf,
                  Span<byte>.Empty,
                  header[..aadLen]);

               sawTerminal = true;

               // After terminal, there MUST be no extra data
               if (input.Read(lenBuf4) != 0)
               {
                  throw new CryptographicException("Trailing data after terminal frame.");
               }

               break;
            }

            var c = cipherBuffer.AsSpan(0, (int)len);
            ReadExactly(input, c);

            var p = plainBuffer.AsSpan(0, (int)len);
            aes.Decrypt(nonceBuf, c, tagBuf, p, header[..aadLen]);
            output.Write(p);

            counter++;
         }

         if (!sawTerminal)
         {
            throw new CryptographicException("Missing terminal authentication frame.");
         }
      }
      finally
      {
         ArrayPool<byte>.Shared.Return(cipherBuffer);
         ArrayPool<byte>.Shared.Return(plainBuffer);
      }
   }

   private static void DeriveNonce(ReadOnlySpan<byte> baseNonce, ulong counter, Span<byte> outNonce)
   {
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
         if (r == 0)
         {
            throw new CryptographicException("Truncated input.");
         }

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

      if (Convert.FromBase64String(key).Length != KeySize)
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