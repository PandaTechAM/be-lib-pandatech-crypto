# Pandatech.Crypto

Unified cryptographic wrapper library for .NET 8+ providing AES encryption, password hashing, compression, and secure random generation.

## Installation

```bash
dotnet add package Pandatech.Crypto
```

## Quick Start

### Configuration (ASP.NET Core)

```csharp
builder.AddAes256Key("your-base64-encoded-256-bit-key");

// Optional: configure Argon2id (defaults shown)
builder.ConfigureArgon2Id(options =>
{
   options.SaltSize = 16;
   options.DegreeOfParallelism = 8;
   options.Iterations = 5;
   options.MemorySize = 128 * 1024; // 128 MB
});
```

## Core Features

### AES-256-GCM (Files & Streams)

Authenticated encryption with associated data. Best for files.

```csharp
// Encrypt
Aes256Gcm.RegisterKey(key);
using var input = File.OpenRead("document.pdf");
using var output = File.Create("document.pdf.enc");
Aes256Gcm.Encrypt(input, output);

// Decrypt
using var encrypted = File.OpenRead("document.pdf.enc");
using var decrypted = File.Create("document.pdf");
Aes256Gcm.Decrypt(encrypted, decrypted);
```

### AES-256-SIV (Deterministic Encryption)

RFC 5297 compliant. Use for PII that needs deterministic matching.

```csharp
Aes256Siv.RegisterKey(key);

byte[] cipher = Aes256Siv.Encrypt("sensitive-data");
string plain = Aes256Siv.Decrypt(cipher);
```

### Argon2id Password Hashing

```csharp
byte[] hash = Argon2Id.HashPassword("user-password");
bool valid = Argon2Id.VerifyHash("user-password", hash);
```

### JWE (RSA-OAEP-256 + AES-256-GCM)

Envelope encryption with JWK keys and RFC 7638 thumbprints.

```csharp
var (publicJwk, privateJwk, kid) = JoseJwe.IssueKeys(bits: 2048);

var jwe = JoseJwe.Encrypt(publicJwk, payload, kid);

if (JoseJwe.TryDecrypt(privateJwk, jwe, out var decrypted))
{
   // use decrypted bytes
}
```

### Secure Random

```csharp
byte[] randomBytes = Random.GenerateBytes(32);
string aesKey = Random.GenerateAes256KeyString();
string token = Random.GenerateSecureToken(); // 256-bit URL-safe
```

### Password Generation & Validation

```csharp
string pwd = Password.GenerateRandom(
   length: 16,
   includeUppercase: true,
   includeLowercase: true,
   includeDigits: true,
   includeSpecialChars: true
);

bool valid = Password.Validate(pwd, minLength: 16, 
   requireUppercase: true, requireLowercase: true, 
   requireDigits: true, requireSpecialChars: true);
```

### Hashing

```csharp
// SHA-2 HMAC
byte[] hmac = Sha2.ComputeHmacSha256(key, "message1", "message2");
string hex = Sha2.GetHmacSha256Hex(key, "message");

// SHA-3
byte[] hash = Sha3.Hash("data");
bool valid = Sha3.VerifyHash("data", hash);
```

### GZip Compression

```csharp
// String
byte[] compressed = GZip.Compress("data");
string decompressed = Encoding.UTF8.GetString(GZip.Decompress(compressed));

// Streams
GZip.Compress(inputStream, outputStream);
GZip.Decompress(inputStream, outputStream);
```

### Data Masking

```csharp
string masked = "user@example.com".MaskEmail();     // "us****@example.com"
string masked = "1234567890".MaskPhoneNumber();     // "******7890"
```

## License

MIT