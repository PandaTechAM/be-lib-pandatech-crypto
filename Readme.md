# 1. PandaTech.Crypto

- [1. PandaTech.Crypto](#1-pandatechcrypto)
    - [1.1. Introduction](#11-introduction)
    - [1.2. Features](#12-features)
    - [1.3. Installation](#13-installation)
    - [1.4. How to Use](#14-how-to-use)
        - [1.4.1. Configuring Dependency Injection](#141-configuring-dependency-injection)
        - [1.4.2. AES256 Class](#142-aes256-class)
            - [1.4.2.1. Immutable Configurations](#1421-immutable-configurations)
            - [1.4.2.2. Encryption/Decryption methods with hashing](#1422-encryptiondecryption-methods-with-hashing)
            - [1.4.2.3. Encryption/Decryption methods without hashing](#1423-encryptiondecryption-methods-without-hashing)
            - [1.4.2.4. Encryption/Decryption methods with custom key (overriding options for one time)](#1424-encryptiondecryption-methods-with-custom-key-overriding-options-for-one-time)
        - [1.4.3. Argon2id Class](#143-argon2id-class)
            - [1.4.3.1. Default Configurations](#1431-default-configurations)
            - [1.4.3.2 Hash password and verify hash](#1432-hash-password-and-verify-hash)
        - [1.4.4. Random Class](#144-random-class)
        - [1.4.5. Password Class](#145-password-class)
        - [1.4.6. Sha3 Class](#146-sha3-class)
        - [1.4.7. GZip Class](#147-gzip-class)
        - [1.4.8. Mask Class](#148-mask-class)
            - [1.4.8.1. Masking Email Addresses](#1481-masking-email-addresses)
    - [1.5. License](#15-license)

## 1.1. Introduction

Pandatech.Crypto is a powerful cryptographic utility library backed by 99% test coverage through unit tests. The library
offers an array of static methods for secure data operations, including AES256 encryption and decryption, Argon2Id
password hashing and verification, as well as utilities for generating cryptographic random bytes and passwords. Now, it
also includes GZip compression and decompression functionalities.

Designed to work efficiently in containerized environments, the library performs effectively even with limited
resources—hash generation takes under 500ms on a container with 1 vCore and 1GB of RAM.

## 1.2. Features

* **AES 256-bit Encryption/Decryption:** Encrypt your data and get the IV and encrypted bytes in one array. Decrypt it
  back to its original form, seamlessly handling the IV. Note that you have option to encrypt with hash and decrypt
  ignoring hash. (for cases where you want to apply filtering on the encrypted data or check uniqueness of the encrypted
  data)
* **Argon2Id Hashing:** Perform password hashing and verification with a focus on security and performance, leveraging
  the Argon2Id algorithm.
* **SHA-3 Hashing:** Utilize 512-bit SHA-3 hashing for various applications.
* **Random Number/Password Generation:** Generate cryptographic random bytes, AES256 keys, or strong passwords with
  specific character sets.
* **GZip Compression/Decompression:** Efficiently compress and decompress data using GZip, with support for byte arrays
  and streams.
* **Masking:** Mask sensitive information like email addresses and phone numbers, ensuring that they are partially
  hidden and thus safeguarded.
* **Performance Optimized:** Tested to run efficiently in resource-constrained environments.
* **High Test Coverage:** Confidence backed by 99% unit test coverage.

## 1.3. Installation

To use `PandaTech.Crypto` in your project, install the NuGet package using the following command in the Package Manager
Console:
`Install-Package PandaTech.Crypto` or, search for "PandaTech.Crypto" in the NuGet Package Manager and install it from
there.

## 1.4. How to Use

### 1.4.1. Configuring Dependency Injection

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

### 1.4.2. AES256 Class

#### 1.4.2.1. Immutable Configurations

1. **IV**: A random IV is generated for each Encryption, enhancing security.
2. **PaddingMode**: PKCS7

#### 1.4.2.2. Encryption/Decryption methods with hashing

```csharp
byte[] cipherText = aes256.Encrypt("your-plaintext");
string plainText = aes256.Decrypt(cipherText);
```

#### 1.4.2.3. Encryption/Decryption methods without hashing

```csharp
byte[] cipherText = aes256.Encrypt("your-plaintext", false);
string plainText = aes256.Decrypt(cipherText, false);
```

#### 1.4.2.4. Encryption/Decryption methods with custom key (overriding options for one time)

```csharp
string customKey = "your-custom-base64-encoded-key";
byte[] cipherText = aes256.Encrypt("your-plaintext", customKey);
string plainText = aes256.Decrypt(cipherText, customKey);
```

### 1.4.3. Argon2id Class

#### 1.4.3.1. Default Configurations

1. **Salt**: A random salt is generated for each password hash, enhancing security.
2. **DegreeOfParallelism**: 8
3. **Iterations**: 5
4. **MemorySize**: 128 MB

#### 1.4.3.2 Hash password and verify hash

```csharp
// Example usage for hashing
var hashedPassword = _argon2Id.HashPassword("yourPassword");

// Example usage for verifying a hash
var isPasswordValid = _argon2Id.VerifyHash("yourPassword", hashedPassword);
```

### 1.4.4. Random Class

```csharp
var randomBytes = Random.GenerateBytes(16);
var aesKey = Random.GenerateAes256KeyString();
```

### 1.4.5. Password Class

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

### 1.4.6. Sha3 Class

```csharp
// Example usage for generating hash
var sha3Hash = Sha3.Hash("yourPlainText");

// Example usage for verifying a hash
var isHashValid = Sha3.VerifyHash("yourPlainText", sha3Hash);
```

### 1.4.7. GZip Class

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

### 1.4.8. Mask Class

The `Mask` class in the PandaTech.Crypto library provides methods to mask sensitive information like email addresses and
phone numbers, ensuring that they are partially hidden and thus safeguarded.

#### 1.4.8.1. Masking Email Addresses

The `MaskEmail` method masks the local part of an email address, showing only the first two characters and replacing the
rest with asterisks (*), keeping the domain part intact.

```csharp
// Example usage for masking an email
string maskedEmail = Mask.MaskEmail("example@email.com");

// Output: "ex*****@email.com"
// Example usage for masking a phone number
string maskedPhone = Mask.MaskPhoneNumber("1234567890");

// Output: "******7890"
```

## 1.5. License

PandaTech.Crypto is licensed under the MIT License.