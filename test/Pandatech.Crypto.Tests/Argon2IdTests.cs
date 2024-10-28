using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto.Tests;

public class Argon2IdTests
{
   [Fact]
   public void HashVerify_ShouldFailForDifferentArgonConfigs()
   {
      var password = Password.GenerateRandom(32, true, true, true, true);
      var options = new Argon2IdOptions
      {
         SaltSize = 16,
         DegreeOfParallelism = 3,
         Iterations = 3,
         MemorySize = 1024
      };
      Argon2Id.Configure(options);
      var hash = Argon2Id.HashPassword(password);
      options.DegreeOfParallelism = 4;
      Argon2Id.Configure(options);
      Assert.False(Argon2Id.VerifyHash(password, hash));
   }

   [Fact]
   public void HashVerify_ShouldBeValid()
   {
      var password = Password.GenerateRandom(32, true, true, true, true);
      var hash = Argon2Id.HashPassword(password);

      Assert.True(Argon2Id.VerifyHash(password, hash));
   }

   [Fact]
   public void HashVerify_InvalidPassword_ShouldBeInvalid()
   {
      var password = Password.GenerateRandom(32, true, true, true, true);
      var hash = Argon2Id.HashPassword(password);
      Assert.False(Argon2Id.VerifyHash("SomePassword", hash));
   }

   [Fact]
   public void DifferentPasswords_ShouldHaveDifferentHashes()
   {
      var password1 = Password.GenerateRandom(32, true, true, true, true);
      var password2 = Password.GenerateRandom(32, true, true, true, true);
      var hash1 = Argon2Id.HashPassword(password1);
      var hash2 = Argon2Id.HashPassword(password2);

      Assert.NotEqual(hash1, hash2);
   }

   [Fact]
   public void HashPassword_EmptyPassword_ShouldThrowException()
   {
      Assert.Throws<ArgumentException>(() => Argon2Id.HashPassword(""));
   }
}