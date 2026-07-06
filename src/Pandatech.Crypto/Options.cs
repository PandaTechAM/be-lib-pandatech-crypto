using Pandatech.Crypto.Helpers;

namespace Pandatech.Crypto;

/// <summary>
///     Configuration options for Argon2id password hashing.
/// </summary>
public class Argon2IdOptions
{
    /// <summary>
    ///     Salt size in bytes. Default is 16.
    /// </summary>
    public int SaltSize { get; set; } = Argon2Id.SaltSize;

    /// <summary>
    ///     Number of parallel threads. Default is 8.
    /// </summary>
    public int DegreeOfParallelism { get; set; } = Argon2Id.DegreeOfParallelism;

    /// <summary>
    ///     Number of iterations. Default is 5.
    /// </summary>
    public int Iterations { get; set; } = Argon2Id.Iterations;

    /// <summary>
    ///     Memory usage in kibibytes. Default is 131072 (128 MB).
    /// </summary>
    public int MemorySize { get; set; } = Argon2Id.MemorySize;
}
