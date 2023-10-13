
# PandaTech.Crypto NuGet Package
PandaTech.Crypto is a .NET library designed to simplify AES256 encryption, decryption, and Argon2id hashing for secure password management. This library aims to provide a straightforward interface for developers while maintaining optimal security configurations for Argon2id.

## Installation
To use `PandaTech.Crypto` in your project, install the NuGet package using the following command in the Package Manager Console:

`bash
Copy code
Install-Package PandaTech.Crypto`
Or, search for "PandaTech.Crypto" in the NuGet Package Manager in Visual Studio and install it from there.

## AES256 Encryption and Decryption
Usage
csharp
Copy code
~~~
// Example usage for encryption
var encryptedData = Aes256.Encrypt("yourPlainText");

// Example usage for decryption
var decryptedData = Aes256.Decrypt(encryptedData);
~~~

### Configuration
**Key**: The AES256 key is retrieved from the environment variable `AES_KEY`. Make sure to set this variable in your environment.
## Argon2id Hashing
### Usage
csharp
Copy code
```
// Example usage for hashing
var hashedPassword = Argon2Id.HashPassword("yourPassword");

// Example usage for verifying a hash
var isPasswordValid = Argon2Id.VerifyHash("yourPassword", hashedPassword);
```
### Configuration
1. **Salt**: A random salt is generated for each password hash, enhancing security.
2. **DegreeOfParallelism**: 8 (configurable) 
3. **Iterations**: 5 (configurable) 
4. **MemorySize**: 128 MB (configurable) 

### Optimal Configurations
The configurations provided by PandaTech.Crypto for Argon2id are optimized for a wide range of server environments. Extensive testing has been conducted, including successful login tests on a server with 1 CPU core and 1 GB of RAM, completing the login process in approximately 1 second.

### Notes
Make sure to set the `AES_KEY` environment variable for AES256 operations.
The library provides default secure configurations for Argon2id, reducing the need for manual adjustments.
Contributions
Contributions to the PandaTech.Crypto library are welcome! Feel free to report issues, suggest improvements, or submit pull requests on GitHub.

License
PandaTech.Crypto is licensed under the MIT License.

PandaTech.Crypto - Simplifying AES256 Encryption, Decryption, and Argon2id Hashing.

Your Security, Our Priority.