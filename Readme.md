# PandaTech.Crypto

## Introduction

**PandaTech.Crypto** is a **wrapper library** that consolidates several widely used cryptographic libraries and tools
into one **simple-to-use package**. This means no more juggling multiple dependencies, heavy `using` directives, or
scattered code to handle everyday cryptographic tasks. The library provides an **intuitive API** that streamlines the *
*most popular** operations:

- AES encryption (including a straightforward **AES256-SIV** implementation not natively offered by Microsoft or
  BouncyCastle),
- Hashing (Argon2Id, SHA2, SHA3),
- GZip compression,
- Secure random generation,
- Password validation/strength checks,
- Masking of sensitive data.
- JOSE (**JWE only**): simple sealed-envelope encryption (RSA-OAEP-256 + AES-256-GCM) with JWK + `kid` thumbprint.

Whether you need to **encrypt data**, **hash passwords**, or **generate secure random tokens**, PandaTech.Crypto
provides lightweight abstractions over popular cryptographic solutions, ensuring simplicity and usability without
sacrificing performance.

**Argon2Id** password hashing is optimized to run efficiently even in **resource-constrained environments** (e.g., under
500 ms on a container with 1 vCore and 1 GB of RAM). Other operations—such as **AES encryption**, **SHA** hashing, and *
*GZip** compression—are lightweight enough for almost any environment.

## Installation

Install the NuGet package via the Package Manager Console:

```bash
Install-Package Pandatech.Crypto
```

## How to Use

### Configuring in Program.cs

Use the following code to configure AES256/AES256-SIV and Argon2Id in your `Program.cs`:

```csharp
using Pandatech.Crypto.Helpers;
using Pandatech.Crypto.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.AddAes256Key("YourBase64EncodedAes256KeyHere");

// Optional - Change default Argon2Id configurations. If below method is not called, default configurations will be used.
builder.ConfigureArgon2Id(options =>
{
   options.SaltSize = 16;
   options.DegreeOfParallelism = 8;
   options.Iterations = 5;
   options.MemorySize = 128 * 1024;
}); 

var app = builder.Build();

app.Run();
```

### 🔥 Breaking change (short) Version 5 to 6

We introduced **two intentional** changes to make usage clearer and safer:

1. `Aes256Siv` **is now RFC-5297 compliant**.
   The previous, non-standard implementation is renamed `Aes256SivLegacy` (compat only).

New `Aes256Gcm` for files.
Fully compliant AES-GCM with framed streaming and truncation detection. Prefer this for files of any size.

#### What you must do

- If you previously called `Aes256Siv`, rename those references to `Aes256SivLegacy` to keep current data working.
- When ready, migrate legacy ciphertexts to the new format using `AesSivMigration` (single/batch helpers).
- For files, use `Aes256Gcm` instead of SIV.

> That’s it. This section is intentionally short—see API notes below.

### 🔥 Breaking change Version 4 to 5

> Warning
> `Aes256` is now deprecated because it used a SHA3 hash for deterministic output, which can weaken overall security.
> For
> new development, use `Aes256Siv` instead.
> For existing data, see the `AesMigration` class below to migrate old ciphertext to the new SIV format.

**Encryption/Decryption methods with hashing**

```csharp
using Pandatech.Crypto.Helpers;

// Encrypt using AES256
var encryptedBytes = Aes256.Encrypt("your-plaintext");

// Decrypt AES256-encrypted data
var decryptedText = Aes256.Decrypt(encryptedBytes);

```

**Encryption/Decryption methods without hashing**

```csharp
byte[] cipherText = aes256.EncryptWithoutHash("your-plaintext");
string plainText = aes256.DecryptWithoutHash(cipherText);
```

**Encryption/Decryption methods with custom key (overriding options for one time)**

```csharp
string customKey = "your-custom-base64-encoded-key";

// Encrypt with a custom key
var encrypted = Aes256.Encrypt("your-plaintext", customKey);

// Decrypt with the same key
var decrypted = Aes256.Decrypt(encrypted, customKey);
```

**Stream-based Encryption/Decryption methods**

```csharp
using var inputStream = new MemoryStream(Encoding.UTF8.GetBytes("your-plaintext"));
using var outputStream = new MemoryStream();

// Encrypt stream
Aes256.Encrypt(inputStream, outputStream, "your-base64-key");

// Decrypt stream
using var decryptedStream = new MemoryStream(outputStream.ToArray());
Aes256.Decrypt(decryptedStream, outputStream, "your-base64-key");
string decryptedText = Encoding.UTF8.GetString(outputStream.ToArray());
```

**Notes**

1. **IV**: A random IV is generated for each Encryption, enhancing security.
2. **PaddingMode**: PKCS7
3. **Hashing**: The AES256 class by defaults also uses SHA3 512 hash before encryption and stores it in front of byte
   array in order to be able to do unique cheques and other operations on encrypted fields. For example imagine you are
   encrypting emails in your software and also want that emails to be unique. With our Aes256 class by default your
   emails will be unique as in front will be the unique hash.

### Aes256Gcm - Perfect for files

**Use this for: images, videos, audio, PDF, XLSX, PPTX, etc.**

- AEAD (confidentiality + integrity)
- Bounded memory, chunked frames (`64 KiB` by default)
- Detects clean truncation via a terminal 0-length authenticated frame

```csharp
// Encrypt
Aes256Gcm.RegisterKey(key);
using var fin  = File.OpenRead("report.pdf");
using var fout = File.Create("report.pdf.gcm");
Aes256Gcm.Encrypt(fin, fout);

// decrypt
using var ein  = File.OpenRead("report.pdf.gcm");
using var eout = File.Create("report.dec.pdf");
Aes256Gcm.Decrypt(ein, eout);
```

> Tip: You can pass a per-call override key: Encrypt(fin, fout, key) / Decrypt(...).

### Aes256Siv - Deterministic and perfect for PII

Use this for PII you need to **match deterministically** (e.g., names/IDs) and decrypt later.
This is **spec-correct AES-SIV (RFC-5297)**: CMAC S2V + masked CTR, output is `V(16B) || C`.

```csharp
Aes256Siv.RegisterKey(key);

byte[] cipher = Aes256Siv.Encrypt("John Q Public");
string plain  = Aes256Siv.Decrypt(cipher);

// byte[] API
var c2 = Aes256Siv.Encrypt(dataBytes);
var p2 = Aes256Siv.DecryptToBytes(c2);
```

> Note: SIV is two-pass by design → not ideal for big files. Use GCM for files.

### AesMigration

If you have data encrypted with the old `Aes256` approach—either hashed or non-hashed—and want to convert it to the new
`Aes256Siv` format, **AesMigration** can help:

```csharp
using Pandatech.Crypto.Helpers;

// Convert a single ciphertext that was hashed (Aes256.Encrypt(...))
byte[] newCipher = AesMigration.MigrateFromOldHashed(oldCiphertext);

// Convert multiple hashed ciphertexts:
List<byte[]> newCipherList = AesMigration.MigrateFromOldHashed(oldCipherList);
```

Similarly for **non-hashed** old ciphertext:

```csharp
byte[] newCipher = AesMigration.MigrateFromOldNonHashed(oldCiphertext);
```

The library provides nullable-friendly variants too (`MigrateFromOldHashedNullable`, etc.).

### JoseJwe — Simple JWE (RSA-OAEP-256 + A256GCM)

Confidentiality-only envelopes using JOSE **JWE** (no signatures). Keys are **RSA JWKs**, and `kid` is the **RFC 7638
thumbprint** of the public JWK.

```csharp
using Pandatech.Crypto.Helpers;
using System.Text;

// 1) Issue RSA keys (2048+)
// returns public/private JWKs and kid (thumbprint of public JWK)
var (publicJwk, privateJwk, kid) = JoseJwe.IssueKeys();

// 2) Encrypt to recipient’s public key (header includes kid)
var plaintext = Encoding.UTF8.GetBytes("hello");
var jwe = JoseJwe.Encrypt(publicJwk, plaintext, kid);

// 3) Decrypt with recipient’s private key
if (JoseJwe.TryDecrypt(privateJwk, jwe, out var bytes))
{
   var text = Encoding.UTF8.GetString(bytes);
}
```

#### Security notes
- RSA key **size ≥ 2048** bits (enforced).
- `kid` must match the supplied `publicJwk` (enforced).
- This is **encryption only** (no authenticity). If you need signing later, add JWS separately.

### Argon2id Class

**Default Configurations**

1. **Salt**: A random salt is generated for each password hash, enhancing security.
2. **DegreeOfParallelism**: 8
3. **Iterations**: 5
4. **MemorySize**: 128 MB

**Examples on usage**

```csharp
using Pandatech.Crypto.Helpers;

// Hash a password using Argon2Id
var hashedPassword = Argon2Id.HashPassword("yourPassword");

// Verify a hashed password
bool isValid = Argon2Id.VerifyHash("yourPassword", hashedPassword);
```

### Random Class

```csharp
var randomBytes = Random.GenerateBytes(16);
var aesKey = Random.GenerateAes256KeyString();
var unimaginableUniqueAndRandomToken = Random.GenerateSecureToken() //256-bit token in string format
```

### Password Class

```csharp
var includeUppercase = true;
var includeLowercase = true;
var includeDigits = true;
var includeSpecialChars = true;

//Method for generating random password
string password = Password.GenerateRandom(16, includeUppercase, includeLowercase, includeDigits, includeSpecialChars);

//Method for validation of password
bool isValid = Password.Validate(password, 16, includeUppercase, includeLowercase, includeDigits, includeSpecialChars);
```

### Sha2 Class

The `Sha2` class simplifies HMAC-SHA256 operations by offering byte array, hex, and Base64 outputs. It also hat params
string[] where the method automatically concatenates all strings and then computes the hash.

```csharp
// Prepare the key and message
var key = Encoding.UTF8.GetBytes("secret");
var message1 = "Hello";
var message2 = "World";

// Compute HMAC-SHA256 as a byte array
byte[] hashBytes = Sha2.ComputeHmacSha256(key, message1, message2);

// Get HMAC-SHA256 as a hex string
string hexHash = Sha2.GetHmacSha256Hex(key, message1, message2);
// Output: 2e91612bb72b29d82f32789d063de62d5897a4ee5d3b5d34459801b94397b099

// Get HMAC-SHA256 as a Base64 string
string base64Hash = Sha2.GetHmacSha256Base64(key, message1, message2);
// Output: LpFhK7crKdgvMnidBj3mLViXpO5dO100RZgBuUOXsJk=
```

### Sha3 Class

```csharp
// Example usage for generating hash
var sha3Hash = Sha3.Hash("yourPlainText");

// Example usage for verifying a hash
var isHashValid = Sha3.VerifyHash("yourPlainText", sha3Hash);
```

### GZip Class

Compression and Decompression
The `GZip` class provides methods for compressing and decompressing data using GZip. It supports operations on strings,
byte arrays, and streams.

Example usage for compressing and decompressing a string:

```csharp
using Pandatech.Crypto;

// Compress a string
string data = "Sample Data";
byte[] compressedData = GZip.Compress(data);

// Decompress back to string
string decompressedData = Encoding.UTF8.GetString(GZip.Decompress(compressedData));
```

Example usage for compressing and decompressing with streams:

```csharp
using var inputStream = new MemoryStream(Encoding.UTF8.GetBytes("Sample Data"));
using var compressedStream = new MemoryStream();
GZip.Compress(inputStream, compressedStream);
byte[] compressedData = compressedStream.ToArray();

using var inputStream = new MemoryStream(compressedData);
using var decompressedStream = new MemoryStream();
GZip.Decompress(inputStream, decompressedStream);
string decompressedData = Encoding.UTF8.GetString(decompressedStream.ToArray());
```

### Mask Class

The `Mask` class in the PandaTech.Crypto library provides methods to mask sensitive information like email addresses and
phone numbers, ensuring that they are partially hidden and thus safeguarded.

#### Masking Email Addresses

The `MaskEmail` method masks the local part of an email address, showing only the first two characters and replacing the
rest with asterisks (*), keeping the domain part intact.

```csharp
// Example usage for masking an email
string maskedEmail = Mask.MaskEmail("example@email.com");

// Output: "ex*****@email.com"
// Example usage for masking a phone number
string maskedPhone = Mask.MaskPhoneNumber("1234567890");

// Output: "******7890"

// You can also use the MaskEmail and MaskPhoneNumber methods as extension methods on strings
string maskedEmail = "example@email.com";
string maskedPhone = "1234567890";

string maskedEmail = maskedEmail.MaskEmail();
string maskedPhone = maskedPhone.MaskPhoneNumber();
```

## License

PandaTech.Crypto is licensed under the MIT License.