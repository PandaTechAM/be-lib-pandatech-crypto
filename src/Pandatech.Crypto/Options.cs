using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto;

public class Argon2IdOptions
{
   public int SaltSize { get; set; } = Argon2Id.SaltSize;
   public int DegreeOfParallelism { get; set; } = Argon2Id.DegreeOfParallelism;
   public int Iterations { get; set; } = Argon2Id.Iterations;
   public int MemorySize { get; set; } = Argon2Id.MemorySize;
}