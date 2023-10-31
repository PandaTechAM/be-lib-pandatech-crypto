using System.Security.Cryptography;

namespace Pandatech.Crypto;

public class Aes256
{
    private readonly Aes256Options _options;
    private const int KeySize = 256;
    private const int IvSize = 16;
    private const int HashSize = 64;

    public Aes256(Aes256Options options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public byte[] Encrypt(string plainText, string? key = null)
    {
        key ??= _options.Key;
        ValidateInputs(plainText, key);
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

    public string Decrypt(byte[] cipherText, string? key = null)
    {
        key ??= _options.Key;
        ValidateInputs(cipherText, key);
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

    public byte[] EncryptWithHash(string plainText, string? key = null)
    {
        key ??= _options.Key;
        var encryptedBytes = Encrypt(plainText, key);
        var hashBytes = Sha3.Hash(plainText);
        return hashBytes.Concat(encryptedBytes).ToArray();
    }

    public string DecryptIgnoringHash(IEnumerable<byte> cipherTextWithHash, string? key = null)
    {
        key ??= _options.Key;
        var cipherText = cipherTextWithHash.Skip(HashSize).ToArray();
        return Decrypt(cipherText, key);
    }

    private static void ValidateInputs(string text, string key)
    {
        if (string.IsNullOrEmpty(text))
            throw new ArgumentException("Text cannot be null or empty.");

        if (string.IsNullOrEmpty(key) || !IsBase64String(key) || Convert.FromBase64String(key).Length != 32)
            throw new ArgumentException("Invalid key.");
    }

    private static void ValidateInputs(byte[] cipherText, string key)
    {
        if (cipherText == null || cipherText.Length < IvSize)
            throw new ArgumentException("Invalid cipher text.");

        if (string.IsNullOrEmpty(key) || !IsBase64String(key) || Convert.FromBase64String(key).Length != 32)
            throw new ArgumentException("Invalid key.");
    }

    private static bool IsBase64String(string s)
    {
        var buffer = new Span<byte>(new byte[s.Length]);
        return Convert.TryFromBase64String(s, buffer, out _);
    }
}