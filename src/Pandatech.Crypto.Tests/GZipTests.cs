using System.Text;

namespace Pandatech.Crypto.Tests;

public class GZipTests
{
    [Fact]
    public void Compress_String_ReturnsCompressedData()
    {
        // Arrange
        const string input = "Hello, world!";
        var expected = GZip.Compress(Encoding.UTF8.GetBytes(input));

        // Act
        var result = GZip.Compress(input);

        // Assert
        Assert.Equal(expected, result);
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
        var input = Encoding.UTF8.GetBytes("Hello, world!");

        // Act
        var compressed = GZip.Compress(input);
        var decompressed = GZip.Decompress(compressed);

        // Assert
        Assert.Equal(input, decompressed);
    }

    [Fact]
    public void Compress_And_Decompress_Stream_ReturnsOriginalData()
    {
        // Arrange
        var input = "Hello, world!"u8.ToArray();
        using var inputStream = new MemoryStream(input);
        using var compressedStream = new MemoryStream();
        using var decompressedStream = new MemoryStream();

        // Act
        GZip.Compress(inputStream, compressedStream);
        compressedStream.Seek(0, SeekOrigin.Begin);
        GZip.Decompress(compressedStream, decompressedStream);
        var result = decompressedStream.ToArray();

        // Assert
        Assert.Equal(input, result);
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
}