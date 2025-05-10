# DES (Data Encryption Standard) Implementation in Java

This repository contains a **Java implementation of the Data Encryption Standard (DES)** algorithm, designed to encrypt and decrypt data using the well-known symmetric key encryption technique. DES is a block cipher that encrypts data in 64-bit blocks using a 56-bit key.

## Features

* **Encryption & Decryption**: Supports encryption and decryption of data using DES.
* **Key Generation**: Generates a 56-bit key for use in encryption and decryption.
* **Permutation and Substitution**: Implements the necessary initial and final permutations, as well as the S-box substitution steps.
* **Feistel Network**: Utilizes the Feistel network for processing the data.

## Prerequisites

* Java 8 or higher
* IDE like IntelliJ IDEA, Eclipse, or a basic text editor and terminal to compile and run the Java files.

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/your-username/des-java.git
   ```

2. **Navigate to the project directory**:

   ```bash
   cd des-java
   ```

3. **Compile the Java code**:

   ```bash
   javac DES.java
   ```

4. **Run the program**:

   ```bash
   java DES
   ```

## Usage

The program can be used to encrypt and decrypt data by calling the respective methods with a plaintext and a key.

### Example:

```java
public class Main {
    public static void main(String[] args) {
        String plaintext = "12345678";  // Example 64-bit block of plaintext
        String key = "1234567890ABCDEF";  // Example 56-bit key
        
        DES des = new DES();
        
        // Encrypt the plaintext
        String ciphertext = des.encrypt(plaintext, key);
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the ciphertext
        String decryptedText = des.decrypt(ciphertext, key);
        System.out.println("Decrypted text: " + decryptedText);
    }
}
```

* **Encryption**: `encrypt(plaintext, key)` will encrypt the plaintext using the given key.
* **Decryption**: `decrypt(ciphertext, key)` will decrypt the ciphertext using the same key.

## Explanation

1. **Key Expansion**: The key is permuted and split into 16 subkeys for each round.
2. **Feistel Structure**: The data undergoes 16 rounds of the Feistel network with the key applied in each round.
3. **S-box Substitution**: Data is substituted using the S-boxes, adding confusion to the encryption.
4. **Permutations**: Initial and final permutations are applied to the data block.

## Contributing

Contributions are welcome! Feel free to fork the repository, submit issues, and create pull requests for improvements.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
