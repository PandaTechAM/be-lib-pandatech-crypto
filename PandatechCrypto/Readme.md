# PandaTech.Crypto
## Introduction
Pandatech.Crypto is a powerful cryptographic utility library backed by 99% test coverage through unit tests. The library offers an array of static methods for secure data operations, including AES256 encryption and decryption, Argon2Id password hashing and verification, as well as utilities for generating cryptographic random bytes and passwords.

Designed to work efficiently in containerized environments, the library performs effectively even with limited resources—hash generation takes under 500ms on a container with 1 vCore and 1GB of RAM.

## Features
* **AES 256-bit Encryption/Decryption:** Encrypt your data and get the IV and encrypted bytes in one array. Decrypt it back to its original form, seamlessly handling the IV.
* **Argon2Id Hashing:** Hash and verify passwords securely with an immutable configuration that's optimized for performance.
* **Random Number/Password Generation:** Generate cryptographic random bytes, AES256 keys, or strong passwords with specific character sets.
* **Performance Optimized:** Tested to run efficiently in resource-constrained environments.
* **High Test Coverage:** Confidence backed by 99% unit test coverage.

## Installation

To use `PandaTech.Crypto` in your project, install the NuGet package using the following command in the Package Manager Console:
`Install-Package PandaTech.Crypto` or, search for "PandaTech.Crypto" in the NuGet Package Manager and install it from there.

## How to Use

### 1. AES256 Class
#### Configurations
1. **IV**: A random IV is generated for each Encryption, enhancing security.
2. **PaddingMode**: PKCS7

Encryption and decryption with environment variable key
```csharp
Environment.SetEnvironmentVariable("AES_KEY", Random.GenerateAes256KeyString());

// Example usage for encryption
var encryptedData = Aes256.Encrypt("yourPlainText");

// Example usage for decryption
var decryptedData = Aes256.Decrypt(encryptedData);
```

### 2. Argon2id Class
#### Configurations
1. **Salt**: A random salt is generated for each password hash, enhancing security.
2. **DegreeOfParallelism**: 8 
3. **Iterations**: 5 
4. **MemorySize**: 128 MB

Hash password and verify hash
```csharp
// Example usage for hashing
var hashedPassword = Argon2Id.HashPassword("yourPassword");

// Example usage for verifying a hash
var isPasswordValid = Argon2Id.VerifyHash("yourPassword", hashedPassword);
```
### 3. Random Class
```csharp
var randomBytes = Random.GenerateBytes(16);
var aesKey = Random.GenerateAes256KeyString();
```

### 4. RandomPassword Class
```csharp
var includeUppercase = true;
var includeLowercase = true;
var includeDigits = true;
var includeSpecialChars = true;
string password = RandomPassword.Generate(16, includeUppercase, includeLowercase, includeDigits, includeSpecialChars);
```

## License
PandaTech.Crypto is licensed under the MIT License.

PandaTech.Crypto - Simplifying AES256 Encryption, Decryption, and Argon2id Hashing.

Your Security, Our Priority.