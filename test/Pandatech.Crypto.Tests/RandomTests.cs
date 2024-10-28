using Random = Pandatech.Crypto.Helpers.Random;

namespace Pandatech.Crypto.Tests;

public class RandomTests
{
   [Fact]
   public void Generate_ShouldReturnByteArray()
   {
      const int length = 16;
      var randomBytes = Random.GenerateBytes(length);

      Assert.NotNull(randomBytes);
      Assert.Equal(length, randomBytes.Length);
   }


   [Fact]
   public void GeneratePandaId_WithNonZeroPreviousId_ReturnsIncrementedId()
   {
      const long previousId = 1_000_000;
      for (var i = 0; i < 1_000_000; ++i)
      {
         var newId = Random.GenerateIdWithVariableSequence(previousId);

         Assert.True(newId > previousId);
      }
   }

   [Fact]
   public void GeneratePandaId_WithinReasonableIterations_DoesNotProduceDuplicates()
   {
      long previousId = 0;

      for (var i = 0; i < 1_000_000; ++i)
      {
         var id = Random.GenerateIdWithVariableSequence(previousId);
         Assert.NotEqual(previousId, id);
         previousId = id;
      }
   }

   [Fact]
   public void GenerateSecureToken_ShouldReturnValidUrlSafeString()
   {
      var token = Random.GenerateSecureToken();

      Assert.NotNull(token);
      Assert.Equal(43, token.Length); // 32 bytes => 43 Base64 characters (without padding)
      Assert.DoesNotContain("+", token);
      Assert.DoesNotContain("/", token);
      Assert.DoesNotContain("=", token);
   }

   [Fact]
   public void GenerateShortUniqueString_ShouldReturnValidUrlSafeString()
   {
      var uniqueString = Random.GenerateShortUniqueString();

      Assert.NotNull(uniqueString);
      Assert.Equal(16, uniqueString.Length); // 12 bytes -> 16 Base64 characters without padding
      Assert.DoesNotContain("+", uniqueString);
      Assert.DoesNotContain("/", uniqueString);
      Assert.DoesNotContain("=", uniqueString);
   }
}