# PandaTech.Crypto

## Introduction

Pandatech.Crypto is a powerful cryptographic utility library backed by 99% test coverage through unit tests. The library
offers an array of static methods for secure data operations, including AES256 encryption and decryption, Argon2Id
password hashing and verification, as well as utilities for generating cryptographic random bytes and passwords.

Designed to work efficiently in containerized environments, the library performs effectively even with limited
resources—hash generation takes under 500ms on a container with 1 vCore and 1GB of RAM.

## Features

* **AES 256-bit Encryption/Decryption:** Encrypt your data and get the IV and encrypted bytes in one array. Decrypt it
  back to its original form, seamlessly handling the IV. Note that you have option to encrypt with hash and decrypt
  ignoring hash. (for cases where you want to apply filtering on the encrypted data or check uniqueness of the encrypted
  data)
* **Argon2Id Hashing:** Perform password hashing and verification with a focus on security and performance, leveraging
  the Argon2Id algorithm.
* **SHA-3 Hashing:** Utilize 512-bit SHA-3 hashing for various applications.
* **Random Number/Password Generation:** Generate cryptographic random bytes, AES256 keys, or strong passwords with
  specific character sets.
* **Performance Optimized:** Tested to run efficiently in resource-constrained environments.
* **High Test Coverage:** Confidence backed by 99% unit test coverage.

## Installation

To use `PandaTech.Crypto` in your project, install the NuGet package using the following command in the Package Manager
Console:
`Install-Package PandaTech.Crypto` or, search for "PandaTech.Crypto" in the NuGet Package Manager and install it from
there.

## How to Use

### 1. Configuring Dependency Injection

First, you'll need to configure Aes256 and Argon2Id in your application. To do so, add the following code to
your `Program.cs` file:

```csharp
using Pandatech.Crypto;

// For Aes256
builder.services.AddPandatechCryptoAes256(options =>
{
  options.Key = "YourAes256KeyHere"; // Make sure to use a secure key
});

// For Argon2Id overriding default configurations
  builder.services.AddPandatechCryptoArgon2Id(options =>
{
   options.SaltSize = 16;
   options.DegreeOfParallelism = 8;
   options.Iterations = 5;
   options.MemorySize = 128 * 1024;
});
```

### 2. AES256 Class

#### Immutable Configurations

1. **IV**: A random IV is generated for each Encryption, enhancing security.
2. **PaddingMode**: PKCS7

#### Encryption/Decryption methods with hashing

```csharp
byte[] cipherText = aes256.Encrypt("your-plaintext");
string plainText = aes256.Decrypt(cipherText);
```

#### Encryption/Decryption methods without hashing

```csharp
byte[] cipherText = aes256.Encrypt("your-plaintext", false);
string plainText = aes256.Decrypt(cipherText, false);
```

#### Encryption/Decryption methods with custom key (overriding options for one time)

```csharp
string customKey = "your-custom-base64-encoded-key";
byte[] cipherText = aes256.Encrypt("your-plaintext", customKey);
string plainText = aes256.Decrypt(cipherText, customKey);
```

### 2. Argon2id Class

#### Default Configurations

1. **Salt**: A random salt is generated for each password hash, enhancing security.
2. **DegreeOfParallelism**: 8
3. **Iterations**: 5
4. **MemorySize**: 128 MB

Hash password and verify hash

```csharp
// Example usage for hashing
var hashedPassword = _argon2Id.HashPassword("yourPassword");

// Example usage for verifying a hash
var isPasswordValid = _argon2Id.VerifyHash("yourPassword", hashedPassword);
```

### 3. Random Class

```csharp
var randomBytes = Random.GenerateBytes(16);
var aesKey = Random.GenerateAes256KeyString();
```

### 4. Password Class

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

### 5. Sha3 Class

```csharp
// Example usage for generating hash
var sha3Hash = Sha3.Hash("yourPlainText");

// Example usage for verifying a hash
var isHashValid = Sha3.VerifyHash("yourPlainText", sha3Hash);
```

## License

PandaTech.Crypto is licensed under the MIT License.