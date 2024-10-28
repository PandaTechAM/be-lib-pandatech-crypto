using System.Text;
using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Tests;

public class GZipTests
{
   [Fact]
   public void CompressDecompressStream_ShouldReturnOriginalData()
   {
      // Arrange
      var originalData = "MySensitiveData";
      var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(originalData));
      var compressedStream = new MemoryStream();
      var decompressedStream = new MemoryStream();

      // Act - Compress
      GZip.Compress(inputStream, compressedStream);
      compressedStream.Seek(0, SeekOrigin.Begin); // Reset stream position for reading

      // Act - Decompress
      GZip.Decompress(compressedStream, decompressedStream);
      decompressedStream.Seek(0, SeekOrigin.Begin); // Reset stream position for reading
      var resultData = new StreamReader(decompressedStream).ReadToEnd();

      // Assert
      Assert.Equal(originalData, resultData);
   }

   [Fact]
   public void CompressStream_ShouldReduceSizeForCompressibleData()
   {
      // Arrange
      var originalData = new string('a', 1024); // Highly compressible data
      var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(originalData));
      var compressedStream = new MemoryStream();

      // Act
      GZip.Compress(inputStream, compressedStream);

      // Assert
      Assert.True(compressedStream.Length < inputStream.Length);
   }

   [Fact]
   public void DecompressStream_WithCorruptedData_ShouldThrow()
   {
      // Arrange
      var corruptedData = new byte[]
      {
         0x0,
         0x1,
         0x2,
         0x3
      }; // Not valid compressed data
      var inputStream = new MemoryStream(corruptedData);
      var decompressedStream = new MemoryStream();

      // Act & Assert
      Assert.Throws<InvalidDataException>(() => GZip.Decompress(inputStream, decompressedStream));
   }

   [Fact]
   public void CompressDecompressEmptyStream_ShouldHandleGracefully()
   {
      // Arrange
      var emptyStream = new MemoryStream();
      var compressedStream = new MemoryStream();
      var decompressedStream = new MemoryStream();

      // Act
      GZip.Compress(emptyStream, compressedStream);
      compressedStream.Seek(0, SeekOrigin.Begin); // Reset the compressed stream position for reading

      // Act
      GZip.Decompress(compressedStream, decompressedStream);
      decompressedStream.Seek(0, SeekOrigin.Begin); // Reset the decompressed stream position for reading
      var resultData = new StreamReader(decompressedStream).ReadToEnd();

      // Assert
      Assert.Empty(resultData);
   }

   [Fact]
   public void CompressAndDecompress_ShouldReturnOriginalObject()
   {
      var originalObject = new TestClass
      {
         SomeLongId = 1,
         FullName = "Test"
      };

      // Act
      var compressedData = GZip.Compress(originalObject);
      var decompressedObject = GZip.Decompress<TestClass>(compressedData);

      // Assert
      Assert.NotNull(decompressedObject);
      Assert.Equal(originalObject.SomeLongId, decompressedObject.SomeLongId);
      Assert.Equal(originalObject.FullName, decompressedObject.FullName);
   }

   [Fact]
   public void CompressAndDecompress_ShouldReturnOriginalObject2()
   {
      var originalObject = new TestClass
      {
         SomeLongId = 1,
         FullName = "Test"
      };

      // Act
      var compressedData = GZip.Compress(originalObject);
      var stringData = Convert.ToBase64String(compressedData);
      var decompressedObject = GZip.Decompress<TestClass>(stringData);

      // Assert
      Assert.NotNull(decompressedObject);
      Assert.Equal(originalObject.SomeLongId, decompressedObject.SomeLongId);
      Assert.Equal(originalObject.FullName, decompressedObject.FullName);
   }

   [Fact]
   public void Decompress_WithInvalidData_ShouldReturnNull()
   {
      // Arrange
      var invalidData = Encoding.UTF8.GetBytes("Invalid compressed data");

      // Act & Assert
      var exception = Record.Exception(() => GZip.Decompress<TestClass>(invalidData));
      Assert.NotNull(exception);
      Assert.IsType<InvalidDataException>(exception);
   }


   [Fact]
   public void CompressAndDecompress_String_ReturnsOriginalData()
   {
      // Arrange
      const string input = "Hello, world!";

      // Act
      var compressed = GZip.Compress(input);
      var decompressedBytes = GZip.Decompress(compressed);

      // Convert decompressed bytes back to string
      var decompressedString = Encoding.UTF8.GetString(decompressedBytes);

      // Assert
      Assert.Equal(input, decompressedString);
   }

   [Fact]
   public void Decompress_Base64_ReturnsOriginalData()
   {
      // Arrange
      const string input = "Hello, world!";
      var compressed = GZip.Compress(input);
      var compressedBase64 = Convert.ToBase64String(compressed);

      // Act
      var result = GZip.Decompress(compressedBase64);
      var resultString = Encoding.UTF8.GetString(result);

      // Assert
      Assert.Equal(input, resultString);
   }

   [Fact]
   public void Compress_And_Decompress_Byte_Array_ReturnsOriginalData()
   {
      // Arrange
      var input = "Hello, world!";

      // Act
      var compressed = GZip.Compress(input);
      var decompressed = GZip.Decompress(compressed);

      // Assert
      Assert.Equal(input, Encoding.UTF8.GetString(decompressed));
   }

   [Fact]
   public void CompressAndDecompress_ByteArray_ReturnsOriginalData()
   {
      // Arrange
      var input = Encoding.UTF8.GetBytes("Sample text for compression");

      // Act
      var compressed = GZip.Compress(input);
      var decompressed = GZip.Decompress(compressed);

      // Assert
      Assert.Equal(input, decompressed);
   }


   [Theory]
   [InlineData("")]
   [InlineData("Short string")]
   [InlineData("The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")]
   public void Compress_Decompress_String_VariousLengths(string input)
   {
      // Act
      var compressed = GZip.Compress(input);
      var decompressed = GZip.Decompress(Convert.ToBase64String(compressed));
      var resultString = Encoding.UTF8.GetString(decompressed);

      // Assert
      Assert.Equal(input, resultString);
   }

   private class TestClass
   {
      public int SomeLongId { get; init; }
      public string? FullName { get; init; }
   }
}