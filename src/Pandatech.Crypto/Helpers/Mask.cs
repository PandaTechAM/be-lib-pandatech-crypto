using System.Net.Mail;

namespace Pandatech.Crypto.Helpers;

/// <summary>
///     Masking helpers for personally identifiable information.
/// </summary>
public static class Mask
{
    /// <summary>
    ///     Mask the local part of an email address, keeping the first two characters and the domain.
    /// </summary>
    public static string MaskEmail(this string email)
    {
        try
        {
            if (!MailAddress.TryCreate(email, out _))
            {
                throw new ArgumentException("Invalid email format", nameof(email));
            }

            var parts = email.Split('@');
            var localPart = parts[0];
            var domainPart = parts[1];

            var maskedLocalPart =
                localPart.Length <= 2 ? localPart : localPart[..2] + new string('*', localPart.Length - 2);
            return $"{maskedLocalPart}@{domainPart}";
        }
        catch (Exception ex)
        {
            throw new ArgumentException("Invalid email format", nameof(email), ex);
        }
    }

    /// <summary>
    ///     Mask a phone number, keeping only the last four characters.
    /// </summary>
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
