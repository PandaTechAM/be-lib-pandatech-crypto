using RegexBox;

namespace Pandatech.Crypto.Helpers;

public static class Mask
{
   public static string MaskEmail(this string email)
   {
      if (!PandaValidator.IsEmail(email))
      {
         throw new ArgumentException("Invalid email address", nameof(email));
      }

      var parts = email.Split('@');
      var localPart = parts[0];
      var domainPart = parts[1];

      var maskedLocalPart =
         localPart.Length <= 2 ? localPart : localPart[..2] + new string('*', localPart.Length - 2);
      return $"{maskedLocalPart}@{domainPart}";
   }

   public static string MaskPhoneNumber(this string phoneNumber)
   {
      if (string.IsNullOrEmpty(phoneNumber))
      {
         throw new ArgumentException("Invalid phone number", nameof(phoneNumber));
      }

      return phoneNumber.Length <= 4
         ? phoneNumber
         : string.Concat(new string('*', phoneNumber.Length - 4), phoneNumber.AsSpan(phoneNumber.Length - 4));
   }
}