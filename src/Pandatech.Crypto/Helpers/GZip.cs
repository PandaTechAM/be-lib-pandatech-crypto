using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Pandatech.Crypto.Helpers;

/// <summary>
///     GZip compression and decompression for streams, strings, byte arrays and JSON-serializable objects.
/// </summary>
public static class GZip
{
    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    ///     Compress a stream into another stream.
    /// </summary>
    public static void Compress(Stream inputStream, Stream outputStream)
    {
        using var gzipStream = new GZipStream(outputStream, CompressionMode.Compress, true);
        inputStream.CopyTo(gzipStream);
    }

    /// <summary>
    ///     Compress a UTF-8 string.
    /// </summary>
    public static byte[] Compress(string data)
    {
        using var memoryStream = new MemoryStream();
        using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress))
        {
            using (var writer = new StreamWriter(gzipStream, Encoding.UTF8))
            {
                writer.Write(data);
            }
        }

        var compressedData = memoryStream.ToArray();

        return compressedData;
    }

    /// <summary>
    ///     Serialize an object to camelCase JSON and compress it.
    /// </summary>
    public static byte[] Compress<T>(T obj)
    {
        var jsonString = JsonSerializer.Serialize(obj, JsonSerializerOptions);
        return Compress(jsonString);
    }


    /// <summary>
    ///     Compress a byte array.
    /// </summary>
    public static byte[] Compress(byte[] data)
    {
        using var memoryStream = new MemoryStream();
        using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress))
        {
            gzipStream.Write(data, 0, data.Length);
        }

        return memoryStream.ToArray();
    }

    /// <summary>
    ///     Decompress a stream into another stream.
    /// </summary>
    public static void Decompress(Stream inputStream, Stream outputStream)
    {
        using var gzipStream = new GZipStream(inputStream, CompressionMode.Decompress, true);
        gzipStream.CopyTo(outputStream);
    }


    /// <summary>
    ///     Decompress a byte array and deserialize its JSON content to an object.
    /// </summary>
    public static T? Decompress<T>(byte[] compressedData)
    {
        var decompressed = Decompress(compressedData);
        var jsonString = Encoding.UTF8.GetString(decompressed);
        return JsonSerializer.Deserialize<T>(jsonString, JsonSerializerOptions);
    }

    /// <summary>
    ///     Decompress a Base64-encoded compressed string and deserialize its JSON content to an object.
    /// </summary>
    public static T? Decompress<T>(string compressedData)
    {
        var decompressed = Decompress(compressedData);
        var jsonString = Encoding.UTF8.GetString(decompressed);
        return JsonSerializer.Deserialize<T>(jsonString, JsonSerializerOptions);
    }

    /// <summary>
    ///     Decompress a Base64-encoded compressed string to bytes.
    /// </summary>
    public static byte[] Decompress(string compressedBase64)
    {
        var compressedData = Convert.FromBase64String(compressedBase64);
        return Decompress(compressedData);
    }

    /// <summary>
    ///     Decompress a byte array to bytes.
    /// </summary>
    public static byte[] Decompress(byte[] data)
    {
        using var compressedStream = new MemoryStream(data);
        using var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzipStream, Encoding.UTF8);
        var decompressedString = reader.ReadToEnd();
        return Encoding.UTF8.GetBytes(decompressedString);
    }
}
