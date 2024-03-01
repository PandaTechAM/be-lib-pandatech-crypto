using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Pandatech.Crypto;

public static class GZip
{
    public static byte[] Compress<T>(T obj)
    {
        var jsonString = JsonSerializer.Serialize(obj);

        var jsonData = Encoding.UTF8.GetBytes(jsonString);

        return Compress(jsonData);
    }

    public static byte[] Compress(string data)
    {
        return Compress(Encoding.UTF8.GetBytes(data));
    }

    public static byte[] Compress(byte[] data)
    {
        using var compressedStream = new MemoryStream();
        Compress(new MemoryStream(data), compressedStream);
        return compressedStream.ToArray();
    }

    public static void Compress(Stream sourceStream, Stream destinationStream)
    {
        using var zipStream = new GZipStream(destinationStream, CompressionMode.Compress, leaveOpen: true);
        sourceStream.CopyTo(zipStream);
    }
    
    public static T? Decompress<T>(byte[] compressedData)
    {
        var decompressedData = Decompress(compressedData);

        var jsonString = Encoding.UTF8.GetString(decompressedData);

        return JsonSerializer.Deserialize<T>(jsonString);
    }

    public static byte[] Decompress(string compressedBase64)
    {
        var compressedData = Convert.FromBase64String(compressedBase64);
        return Decompress(compressedData);
    }

    public static byte[] Decompress(byte[] data)
    {
        using var decompressedStream = new MemoryStream();
        Decompress(new MemoryStream(data), decompressedStream);
        return decompressedStream.ToArray();
    }

    public static void Decompress(Stream sourceStream, Stream destinationStream)
    {
        using var zipStream = new GZipStream(sourceStream, CompressionMode.Decompress, leaveOpen: true);
        zipStream.CopyTo(destinationStream);
    }
}