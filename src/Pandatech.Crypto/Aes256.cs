using System.Security.Cryptography;

namespace Pandatech.Crypto;

public class Aes256(Aes256Options options)
{
    private readonly Aes256Options _options = options ?? throw new ArgumentNullException(nameof(options));
    private const int KeySize = 256;
    private const int IvSize = 16;
    private const int HashSize = 64;

    public byte[] Encrypt(string plainText)
    {
        return EncryptWithHashInner(plainText);
    }

    public byte[] EncryptWithoutHash(string plainText)
    {
        return EncryptWithoutHashInner(plainText, null);
    }

    public byte[] Encrypt(string plainText, string key)
    {
        ValidateKey(key);

        return EncryptWithHashInner(plainText, key);
    }

    public byte[] EncryptWithoutHash(string plainText, string key)
    {
        ValidateKey(key);

        return EncryptWithoutHashInner(plainText, key);
    }

    public void Encrypt(Stream inputStream, Stream outputStream, string? key = null)
    {
        key ??= _options.Key;
        ValidateKey(key);
        using var aesAlg = Aes.Create();
        aesAlg.KeySize = KeySize;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.Key = Convert.FromBase64String(key);
        aesAlg.GenerateIV();

        outputStream.Write(aesAlg.IV, 0, aesAlg.IV.Length);

        using var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
        using var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        inputStream.CopyTo(cryptoStream);
    }

    private byte[] EncryptWithHashInner(string plainText, string? key = null)
    {
        key ??= _options.Key;
        var encryptedBytes = EncryptWithoutHashInner(plainText, key);
        var hashBytes = Sha3.Hash(plainText);
        return hashBytes.Concat(encryptedBytes).ToArray();
    }

    private byte[] EncryptWithoutHashInner(string plainText, string? key)
    {
        key ??= _options.Key;
        ValidateText(plainText);
        using var aesAlg = Aes.Create();
        aesAlg.KeySize = KeySize;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.Key = Convert.FromBase64String(key);

        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using var swEncrypt = new StreamWriter(csEncrypt);
        swEncrypt.Write(plainText);
        swEncrypt.Flush();
        csEncrypt.FlushFinalBlock();

        var encryptedPasswordByte = msEncrypt.ToArray();

        var result = aesAlg.IV.Concat(encryptedPasswordByte).ToArray();
        return result;
    }

    public string Decrypt(byte[] cipherText)
    {
        return cipherText.Length == 0
            ? ""
            : DecryptSkippingHashInner(cipherText);
    }

    public string DecryptWithoutHash(byte[] cipherText)
    {
        return cipherText.Length == 0
            ? ""
            : DecryptWithoutSkippingHashInner(cipherText, null);
    }

    public string Decrypt(byte[] cipherText, string key)
    {
        ValidateKey(key);
        return cipherText.Length == 0
            ? ""
            : DecryptSkippingHashInner(cipherText, key);
    }

    public string DecryptWithoutHash(byte[] cipherText, string key)
    {
        ValidateKey(key);
        return cipherText.Length == 0
            ? ""
            : DecryptWithoutSkippingHashInner(cipherText, key);
    }
    
    public void Decrypt(Stream inputStream, Stream outputStream, string? key = null)
    {
        key ??= _options.Key;
        ValidateKey(key);

        var iv = new byte[IvSize];
        if (inputStream.Read(iv, 0, IvSize) != IvSize)
            throw new ArgumentException("Input stream does not contain a complete IV.");

        using var aesAlg = Aes.Create();
        aesAlg.KeySize = KeySize;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.Key = Convert.FromBase64String(key);
        aesAlg.IV = iv;

        using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        cryptoStream.CopyTo(outputStream);
    }

    private string DecryptWithoutSkippingHashInner(byte[] cipherText, string? key)
    {
        key ??= _options.Key;
        ValidateCipherText(cipherText);
        var iv = cipherText.Take(IvSize).ToArray();
        var encrypted = cipherText.Skip(IvSize).ToArray();

        using var aesAlg = Aes.Create();
        aesAlg.KeySize = KeySize;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.Key = Convert.FromBase64String(key);
        aesAlg.IV = iv;

        var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        using var msDecrypt = new MemoryStream(encrypted);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }

    private string DecryptSkippingHashInner(IEnumerable<byte> cipherTextWithHash, string? key = null)
    {
        key ??= _options.Key;
        var cipherText = cipherTextWithHash.Skip(HashSize).ToArray();
        return DecryptWithoutSkippingHashInner(cipherText, key);
    }

    private static void ValidateKey(string key)
    {
        if (string.IsNullOrEmpty(key) || !IsBase64String(key) || Convert.FromBase64String(key).Length != 32)
            throw new ArgumentException("Invalid key.");
    }

    private static void ValidateText(string text)
    {
        if (string.IsNullOrEmpty(text) && text != null)
            throw new ArgumentException("Text cannot be null or empty.");
    }

    private static void ValidateCipherText(byte[] cipherText)
    {
        if (cipherText.Length == 0) return;

        if (cipherText == null || cipherText.Length < IvSize)
            throw new ArgumentException("Invalid cipher text.");
    }

    private static bool IsBase64String(string s)
    {
        var buffer = new Span<byte>(new byte[s.Length]);
        return Convert.TryFromBase64String(s, buffer, out _);
    }
}