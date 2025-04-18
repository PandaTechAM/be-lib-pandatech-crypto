﻿using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Tests;

public class PasswordTests
{
   [Theory]
   [InlineData(7, true, true, true, true)]
   [InlineData(4, false, true, false, false)]
   [InlineData(5, true, true, true, false)]
   public void Generate_ShouldReturnPasswordWithCorrectProperties(int length,
      bool includeUppercase,
      bool includeLowercase,
      bool includeDigits,
      bool includeSpecialChars)
   {
      // Generate a random password
      var password = Password.GenerateRandom(length,
         includeUppercase,
         includeLowercase,
         includeDigits,
         includeSpecialChars);

      // Check if the password length is correct
      Assert.Equal(length, password.Length);

      // Check if the password contains the correct character sets
      if (includeUppercase)
      {
         Assert.Contains(password, char.IsUpper);
      }

      if (includeLowercase)
      {
         Assert.Contains(password, char.IsLower);
      }

      if (includeDigits)
      {
         Assert.Contains(password, char.IsDigit);
      }

      if (includeSpecialChars)
      {
         Assert.Contains(password, c => "!@#$%^&*()-_=+[]{}|;:'\",.<>?".Contains(c));
      }
   }

   [Fact]
   public void Generate_ShouldReturnDifferentPasswords()
   {
      var password1 = Password.GenerateRandom(12, true, true, true, true);
      var password2 = Password.GenerateRandom(12, true, true, true, true);

      Assert.NotEqual(password1, password2);
   }

   [Theory]
   [InlineData(7, true, false, true, true)]
   [InlineData(4, false, true, false, false)]
   [InlineData(5, true, false, false, false)]
   [InlineData(13, true, true, false, false)]
   [InlineData(25, true, true, true, false)]
   [InlineData(35, true, true, true, true)]
   public void ValidationTestForGeneratedPasswords(int length,
      bool includeUppercase,
      bool includeLowercase,
      bool includeDigits,
      bool includeSpecialChars)
   {
      // Generate a random password
      var password = Password.GenerateRandom(length,
         includeUppercase,
         includeLowercase,
         includeDigits,
         includeSpecialChars);
      Assert.True(Password.Validate(password,
         length,
         includeUppercase,
         includeLowercase,
         includeDigits,
         includeSpecialChars));
   }

   [Theory]
   [InlineData(7, true, false, true, true)]
   [InlineData(4, false, true, false, false)]
   [InlineData(5, true, false, false, false)]
   [InlineData(13, true, true, false, false)]
   [InlineData(25, true, true, true, false)]
   [InlineData(35, false, true, true, true)]
   public void ValidationTestForGeneratedPasswordsOpposite(int length,
      bool includeUppercase,
      bool includeLowercase,
      bool includeDigits,
      bool includeSpecialChars)
   {
      // Generate a random password
      var password = Password.GenerateRandom(length,
         includeUppercase,
         includeLowercase,
         includeDigits,
         includeSpecialChars);
      Assert.False(Password.Validate(password,
         length,
         !includeUppercase,
         !includeLowercase,
         !includeDigits,
         !includeSpecialChars));
   }

   [Fact]
   public void PasswordValidationTests()
   {
      var password1 = "Qwerty123!";
      Assert.True(Password.Validate(password1, 8, false, false, false, false));
   }
}