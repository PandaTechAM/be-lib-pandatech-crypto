namespace Pandatech.Crypto;

public class Aes256Options
{
    public string Key { get; set; } = null!;
}

public class Argon2IdOptions
{
    public int SaltSize { get; set; } = 16;
    public int DegreeOfParallelism { get; set; } = 8;
    public int Iterations { get; set; } = 5;
    public int MemorySize { get; set; } = 128 * 1024; // 128 MB
}