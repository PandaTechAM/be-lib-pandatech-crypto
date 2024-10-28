namespace Pandatech.Crypto.Helpers;

public static class Password
{
   private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
   private const string DigitChars = "0123456789";
   private const string SpecialChars = "!@$*()-_=+[]{}|;:,.";

   public static string GenerateRandom(int length,
      bool includeUppercase,
      bool includeLowercase,
      bool includeDigits,
      bool includeSpecialChars)
   {
      var typesCount = ValidateInput(length, includeUppercase, includeLowercase, includeDigits, includeSpecialChars);

      var charSet = "";
      if (includeUppercase)
      {
         charSet += UppercaseChars;
      }

      if (includeLowercase)
      {
         charSet += LowercaseChars;
      }

      if (includeDigits)
      {
         charSet += DigitChars;
      }

      if (includeSpecialChars)
      {
         charSet += SpecialChars;
      }


      var buffer = Random.GenerateBytes(length - typesCount);
      var requiredBuffer = Random.GenerateBytes(typesCount);

      var password = new char[length];
      for (var i = 0; i < buffer.Length; i++)
      {
         var index = buffer[i] % charSet.Length;
         password[i] = charSet[index];
      }

      var bufferIndex = 0;

      if (includeUppercase)
      {
         var index = requiredBuffer[bufferIndex++] % UppercaseChars.Length;
         password[buffer.Length + bufferIndex - 1] = UppercaseChars[index];
      }

      if (includeLowercase)
      {
         var index = requiredBuffer[bufferIndex++] % LowercaseChars.Length;
         password[buffer.Length + bufferIndex - 1] = LowercaseChars[index];
      }

      if (includeDigits)
      {
         var index = requiredBuffer[bufferIndex++] % DigitChars.Length;
         password[buffer.Length + bufferIndex - 1] = DigitChars[index];
      }

      if (includeSpecialChars)
      {
         var index = requiredBuffer[bufferIndex++] % SpecialChars.Length;
         password[buffer.Length + bufferIndex - 1] = SpecialChars[index];
      }

      return ShuffleString(password);
   }

   public static bool Validate(string password,
      int minLength,
      bool requireUppercase,
      bool requireLowercase,
      bool requireDigits,
      bool requireSpecialChars)
   {
      if (password.Length < minLength)
      {
         return false;
      }

      if (requireUppercase && !password.Any(char.IsUpper))
      {
         return false;
      }

      if (requireLowercase && !password.Any(char.IsLower))
      {
         return false;
      }

      if (requireDigits && !password.Any(char.IsDigit))
      {
         return false;
      }

      if (requireSpecialChars && !password.Any(c => SpecialChars.Contains(c)))
      {
         return false;
      }

      return true;
   }

   private static int ValidateInput(int length,
      bool includeUppercase,
      bool includeLowercase,
      bool includeDigits,
      bool includeSpecialChars)
   {
      var typesCount = (includeUppercase ? 1 : 0) + (includeLowercase ? 1 : 0) + (includeDigits ? 1 : 0) +
                       (includeSpecialChars ? 1 : 0);

      if (typesCount == 0)
      {
         throw new ArgumentException("At least one character set must be selected.");
      }

      if (length < typesCount)
      {
         throw new ArgumentException($"Password length must be at least {typesCount}.");
      }

      return typesCount;
   }

   private static string ShuffleString(char[] array)
   {
      var n = array.Length;
      var randomBuffer = Random.GenerateBytes(n);

      for (var i = n - 1; i >= 1; i--)
      {
         var j = randomBuffer[i] % (i + 1);
         (array[i], array[j]) = (array[j], array[i]);
      }

      return new string(array);
   }
}