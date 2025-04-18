﻿using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Tests;

public class MaskTests
{
   [Theory]
   [InlineData("vazgen.Sargsyan@vazgen.com", "va*************@vazgen.com")]
   [InlineData("test@example.com", "te**@example.com")]
   [InlineData("ab@c.com", "ab@c.com")]
   [InlineData("a@b.com", "a@b.com")]
   public void MaskEmail_ValidEmails_ReturnsMaskedEmail(string input, string expected)
   {
      var result = input.MaskEmail();
      Assert.Equal(expected, result);
   }

   [Theory]
   [InlineData("")]
   [InlineData("notanemail")]
   public void MaskEmail_InvalidEmails_ThrowsArgumentException(string input)
   {
      Assert.Throws<ArgumentException>(input.MaskEmail);
   }

   [Theory]
   [InlineData("1234567890", "******7890")]
   [InlineData("1234", "1234")]
   [InlineData("12", "12")]
   public void MaskPhoneNumber_ValidPhoneNumbers_ReturnsMaskedPhone(string input, string expected)
   {
      var result = input.MaskPhoneNumber();
      Assert.Equal(expected, result);
   }

   [Theory]
   [InlineData(null)]
   [InlineData("")]
   public void MaskPhoneNumber_InvalidPhoneNumbers_ThrowsArgumentException(string input)
   {
      Assert.Throws<ArgumentException>(input.MaskPhoneNumber);
   }
}