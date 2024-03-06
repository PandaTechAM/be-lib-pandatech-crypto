using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Pandatech.Crypto;

public static class GZip
{
    public static byte[] Compress<T>(T obj)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        var jsonString = JsonSerializer.Serialize(obj, options);
        return Compress(jsonString);
    }

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

    public static byte[] Compress(byte[] data)
    {
        using var memoryStream = new MemoryStream();
        using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress))
        {
            gzipStream.Write(data, 0, data.Length);
        }

        return memoryStream.ToArray();
    }

    public static T? Decompress<T>(byte[] compressedData)
    {
        var jsonString = Decompress(compressedData);
        return JsonSerializer.Deserialize<T>(jsonString);
    }

    public static byte[] Decompress(string compressedBase64)
    {
        var compressedData = Convert.FromBase64String(compressedBase64);
        return Decompress(compressedData);
    }

    public static byte[] Decompress(byte[] data)
    {
        using var compressedStream = new MemoryStream(data);
        using var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzipStream, Encoding.UTF8);
        var decompressedString = reader.ReadToEnd();
        return Encoding.UTF8.GetBytes(decompressedString);
    }
}