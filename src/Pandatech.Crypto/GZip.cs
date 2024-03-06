using System.IO.Compression;
using System.Text;
using System.Text.Json;



namespace Pandatech.Crypto;

public static class GZip
{
    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };
    public static byte[] Compress<T>(T obj)
    {
        var jsonString = JsonSerializer.Serialize(obj, JsonSerializerOptions);
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
        var decompressed = Decompress(compressedData);
        var jsonString = Encoding.UTF8.GetString(decompressed);
        return JsonSerializer.Deserialize<T>(jsonString, JsonSerializerOptions);
    }
    
    public static T? Decompress<T>(string compressedData)
    {
        var decompressed = Decompress(compressedData);
        var jsonString = Encoding.UTF8.GetString(decompressed);
        return JsonSerializer.Deserialize<T>(jsonString, JsonSerializerOptions);
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