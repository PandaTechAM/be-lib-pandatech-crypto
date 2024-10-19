# PandaTech.Crypto

## Introduction

PandaTech.Crypto is a **wrapper library** that consolidates several widely used cryptographic libraries and tools into
one
**simple-to-use package**. It eliminates the need for multiple dependencies, excessive `using` directives, and
duplicated
code, offering an **intuitive API** to streamline **most popular** cryptographic tasks.

Whether you need to **encrypt data**, **hash passwords**, or **generate secure random tokens**, PandaTech.Crypto
provides
lightweight abstractions over popular cryptographic solutions, ensuring simplicity and usability without sacrificing
performance.

The **Argon2Id** password hashing is optimized to run efficiently even in **resource-constrained environments** (e.g.,
hash
generation under 500ms on a container with 1 vCore and 1GB of RAM). Other operations such as **AES encryption**, **SHA**
hashing, and **GZip** compression are lightweight enough for almost any environment.

## Installation

Install the NuGet package via the Package Manager Console:

```bash
Install-Package Pandatech.Crypto
```

## How to Use

### Configuring Dependency Injection

Add the following code to your Program.cs file to configure AES256 and Argon2Id services with minimal setup:

```csharp
using Pandatech.Crypto;

// For Aes256
builder.services.AddPandatechCryptoAes256(options =>
{
  options.Key = "YourAes256KeyHere"; // Make sure to use a secure key
});

// For Argon2Id default configuration
builder.services.AddPandatechCryptoArgon2Id();

// For Argon2Id overriding default configurations
  builder.services.AddPandatechCryptoArgon2Id(options =>
{
   options.SaltSize = 16;
   options.DegreeOfParallelism = 8;
   options.Iterations = 5;
   options.MemorySize = 128 * 1024;
});
```

### AES256 Class

**Encryption/Decryption methods with hashing**

```csharp
byte[] cipherText = aes256.Encrypt("your-plaintext");
string plainText = aes256.Decrypt(cipherText);
```

**Encryption/Decryption methods without hashing**

```csharp
byte[] cipherText = aes256.EncryptWithoutHash("your-plaintext");
string plainText = aes256.DecryptWithoutHash(cipherText);
```

**Encryption/Decryption methods with custom key (overriding options for one time)**

```csharp
string customKey = "your-custom-base64-encoded-key";
byte[] cipherText = aes256.Encrypt("your-plaintext", customKey);
string plainText = aes256.Decrypt(cipherText, customKey);
```

**Stream-based Encryption/Decryption methods**

The AES256 class also supports stream-based operations, allowing for encryption and decryption directly on streams,
which is ideal for handling large files or data streams efficiently.

```csharp
using var inputStream = new MemoryStream(Encoding.UTF8.GetBytes("your-plaintext"));
using var outputStream = new MemoryStream();
aes256.EncryptStream(inputStream, outputStream, "your-custom-base64-encoded-key");
byte[] encryptedBytes = outputStream.ToArray();

using var inputStream = new MemoryStream(encryptedBytes);
using var outputStream = new MemoryStream();
aes256.DecryptStream(inputStream, outputStream, "your-custom-base64-encoded-key");
string decryptedText = Encoding.UTF8.GetString(outputStream.ToArray());
```

**Notes**

1. **IV**: A random IV is generated for each Encryption, enhancing security.
2. **PaddingMode**: PKCS7
3. **Hashing**: The AES256 class by defaults also uses SHA3 512 hash before encryption and stores it in front of byte
   array in order to be able to do unique cheques and other operations on encrypted fields. For example imagine you are
   encrypting emails in your software and also want that emails to be unique. With our Aes256 class by default your
   emails will be unique as in front will be the unique hash.


### Argon2id Class

**Default Configurations**

1. **Salt**: A random salt is generated for each password hash, enhancing security.
2. **DegreeOfParallelism**: 8
3. **Iterations**: 5
4. **MemorySize**: 128 MB

**Examples on usage**

```csharp
// Example usage for hashing
var hashedPassword = _argon2Id.HashPassword("yourPassword");

// Example usage for verifying a hash
var isPasswordValid = _argon2Id.VerifyHash("yourPassword", hashedPassword);
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

The `Sha2` class simplifies HMAC-SHA256 operations by offering byte array, hex, and Base64 outputs.

```csharp
// Prepare the key and message
var key = Encoding.UTF8.GetBytes("your-secret-key");
var message = "HelloWorld";

// Compute HMAC-SHA256 as a byte array
byte[] hashBytes = Sha2.ComputeHmacSha256(key, message);

// Get HMAC-SHA256 as a hex string
string hexHash = Sha2.GetHmacSha256Hex(key, message);
// Output: 2e91612bb72b29d82f32789d063de62d5897a4ee5d3b5d34459801b94397b099

// Get HMAC-SHA256 as a Base64 string
string base64Hash = Sha2.GetHmacSha256Base64(key, message);
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