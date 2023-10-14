using System.Security.Cryptography;

namespace Pandatech.Crypto;

public static class RandomPassword
{
    private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    private const string DigitChars = "0123456789";
    private const string SpecialChars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?";

    public static string Generate(int length, bool includeUppercase, bool includeLowercase, bool includeDigits,
        bool includeSpecialChars)
    {
        if (length <= 0)
            throw new ArgumentException("Password length must be greater than zero.");

        var charSet = "";
        if (includeUppercase)
            charSet += UppercaseChars;
        if (includeLowercase)
            charSet += LowercaseChars;
        if (includeDigits)
            charSet += DigitChars;
        if (includeSpecialChars)
            charSet += SpecialChars;

        if (string.IsNullOrEmpty(charSet))
            throw new ArgumentException("At least one character set must be selected.");

        var buffer = Random.GenerateBytes(length);

        var password = new char[length];
        for (var i = 0; i < length; i++)
        {
            var index = buffer[i] % charSet.Length;
            password[i] = charSet[index];
        }

        return new string(password);
    }
}