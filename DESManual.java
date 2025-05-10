package DESManual;

import java.util.Scanner;

/**
 * DESManual - A manual implementation of the Data Encryption Standard (DES) algorithm
 * This class provides methods for encrypting and decrypting data using the DES algorithm,
 * as well as utilities for converting between different data formats.
 */
public class DESManual {
	
	/**
     * Initial Permutation (IP) table
     * This table defines how the 64 bits of input are rearranged before the main rounds
     * of encryption begin. The values indicate which bit from the input goes to each 
     * position in the output.
     */ 
    private static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    /**
     * Final Permutation (FP) table
     * This is the inverse of the Initial Permutation and is applied after all
     * encryption rounds are completed. It rearranges the bits to produce the final output.
     */
    private static final int[] FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    /**
     * Expansion (E) table
     * This table expands the 32-bit right half of the data to 48 bits by duplicating
     * some bits. This expansion matches the 48-bit size of the round key for the XOR operation.
     */
    private static final int[] E = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };
    
    /**
     * Permutation (P) table
     * This table is used in the Feistel function after S-box substitution to
     * rearrange the bits, creating diffusion in the algorithm.
     */
    private static final int[] P = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };
    
    /**
     * Substitution Boxes (S-boxes)
     * These 8 S-boxes transform 6-bit inputs into 4-bit outputs, providing
     * the non-linear component that is crucial for DES security.
     * Each S-box contains 4 rows and 16 columns.
     */
    private static final int[][][] SBOX = {
        // S-box 1
        {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        // S-box 2
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        // S-box 3
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        // S-box 4
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        // S-box 5
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        // S-box 6
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        // S-box 7
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        // S-box 8
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };
    
    /**
     * Permuted Choice 1 (PC1) table
     * Used in key scheduling to reduce the 64-bit key to 56 bits by
     * removing the parity bits (every 8th bit).
     */
    private static final int[] PC1 = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };
    
    /**
     * Permuted Choice 2 (PC2) table
     * Used in key scheduling to transform the 56-bit key into the 48-bit
     * round key needed for each round of encryption.
     */
    private static final int[] PC2 = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };
    
    /**
     * Key shift schedule
     * Specifies the number of left shifts to perform on key halves for each round.
     * Most rounds use 2 shifts, but rounds 1, 2, 9, and 16 use just 1 shift.
     */
    private static final int[] SHIFTS = {
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
    };
    
    /**
     * Converts a hexadecimal string to its binary representation
     * 
     * @param hex The hexadecimal string to convert
     * @return The binary representation as a string of 0s and 1s
     */
    public static String hexToBinary(String hex) {
        StringBuilder binary = new StringBuilder();
        for (int i = 0; i < hex.length(); i++) {
        	// Convert each hex digit to a 4-bit binary value
            int decimal = Integer.parseInt(Character.toString(hex.charAt(i)), 16);
            binary.append(String.format("%4s", Integer.toBinaryString(decimal)).replace(' ', '0'));
        }
        return binary.toString();
    }
    
    /**
     * Converts a binary string to its hexadecimal representation
     * 
     * @param binary The binary string (0s and 1s) to convert
     * @return The hexadecimal representation
     */
    public static String binaryToHex(String binary) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 4) {
            String chunk = binary.substring(i, i + 4);
            int decimal = Integer.parseInt(chunk, 2);
            hex.append(Integer.toHexString(decimal).toUpperCase());
        }
        return hex.toString();
    }

    /**
     * Main method - provides interactive console interface for DES encryption/decryption
     */
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        boolean continueProgram = true;
        
        while (continueProgram) {
            System.out.println("\nDES Encryption and Decryption Implementation");
            System.out.println("-------------------------------------------");
            
            // Get input format preference from user
            System.out.print("Do you want to enter (1) Plaintext or (2) Hexadecimal? ");
            int choice = sc.nextInt();
            sc.nextLine();  // consume leftover newline

            String binaryPlaintext;
            String originalInput;
            
            // Process input based on user choice (text or hex)
            if (choice == 1) {
                System.out.print("Enter 8-byte plaintext: ");
                String plaintext = sc.nextLine();
                // Ensure input is exactly 8 bytes (pad or truncate if needed)
                if (plaintext.length() < 8) {
                    plaintext = String.format("%-8s", plaintext); // Pad with spaces if less than 8 bytes
                } else if (plaintext.length() > 8) {
                    plaintext = plaintext.substring(0, 8); // Truncate if more than 8 bytes
                    System.out.println("Input truncated to 8 bytes: " + plaintext);
                }
                originalInput = plaintext;
                binaryPlaintext = stringToBinary(plaintext);
                System.out.println("Binary representation: " + binaryPlaintext);
            } else {
                System.out.print("Enter 16-digit hexadecimal (8 bytes): ");
                String hex = sc.nextLine();
                // Ensure input is exactly 16 hex digits (pad or truncate if needed)
                if (hex.length() < 16) {
                    hex = String.format("%-16s", hex).replace(' ', '0'); // Pad with zeros if less than 16 hex digits
                } else if (hex.length() > 16) {
                    hex = hex.substring(0, 16); // Truncate if more than 16 hex digits
                    System.out.println("Input truncated to 16 hex digits: " + hex);
                }
                originalInput = hex;
                binaryPlaintext = hexToBinary(hex);
                System.out.println("Binary representation: " + binaryPlaintext);
            }
            
            // Get encryption key from user or generate one
            System.out.print("Enter 8-byte key (or press Enter to generate one automatically): ");
            String key = sc.nextLine();
            
            if (key.isEmpty()) {
            	// Generate a random 8-byte key using printable ASCII character
                StringBuilder randomKey = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    randomKey.append((char)(Math.random() * 94 + 32)); // Printable ASCII characters
                }
                key = randomKey.toString();
                System.out.println("Generated key: " + key);
            } else if (key.length() < 8) {
                key = String.format("%-8s", key); // Pad with spaces if less than 8 bytes
            } else if (key.length() > 8) {
                key = key.substring(0, 8); // Truncate if more than 8 bytes
                System.out.println("Key truncated to 8 bytes: " + key);
            }
            
            String binaryKey = stringToBinary(key);
            System.out.println("Binary key: " + binaryKey);

            // Generate all 16 round keys for encryption/decryption
            String[] roundKeys = generateKeys(binaryKey);
            System.out.println("\n--- Round Keys Generated ---");
            System.out.print("Do you want to see the round keys? (yes/no): ");
            String showKeys = sc.nextLine().toLowerCase();
            if (showKeys.equals("yes") || showKeys.equals("y")) {
                for (int i = 0; i < roundKeys.length; i++) {
                    System.out.println("Round Key " + (i + 1) + ": " + roundKeys[i]);
                }
            }

            // Encryption
            System.out.println("\n--- Encryption ---");
            System.out.println("Original input: " + originalInput);
            
            // Use the quiet version of encrypt for the main result
            String encrypted = encryptQuiet(binaryPlaintext, roundKeys);
            String encryptedHex = binaryToHex(encrypted);
            
            System.out.println("*** ENCRYPTED MESSAGE ***");
            System.out.println("Binary: " + encrypted);
            System.out.println("Hexadecimal: " + encryptedHex);
            
            // Optionally show detailed encryption process
            System.out.print("\nDo you want to see the encryption process details? (yes/no): ");
            String showEncProcess = sc.nextLine().toLowerCase();
            if (showEncProcess.equals("yes") || showEncProcess.equals("y")) {
                System.out.println("\n--- Detailed Encryption Process ---");
                encrypt(binaryPlaintext, roundKeys); // Call the version that prints details
            }

            // Decryption
            System.out.print("\nDo you want to decrypt the message? (yes/no): ");
            String performDecryption = sc.nextLine().toLowerCase();
            
            if (performDecryption.equals("yes") || performDecryption.equals("y")) {
                System.out.println("\n--- Decryption ---");
                
                // Create a version of decrypt that doesn't print the process
                String decrypted = decryptQuiet(encrypted, roundKeys);
                
                System.out.println("*** DECRYPTED MESSAGE ***");
                System.out.println("Binary: " + decrypted);
                
             // Display result in the original format (text or hex)
                if (choice == 1) {
                    System.out.println("Plaintext: " + binaryToString(decrypted));
                } else {
                    System.out.println("Hexadecimal: " + binaryToHex(decrypted));
                }
               
                // Optionally show detailed decryption process
                System.out.print("\nDo you want to see the decryption process details? (yes/no): ");
                String showDecProcess = sc.nextLine().toLowerCase();
                if (showDecProcess.equals("yes") || showDecProcess.equals("y")) {
                    System.out.println("\n--- Detailed Decryption Process ---");
                    decrypt(encrypted, roundKeys); // Call the version that prints details
                }
            }
            
            // Ask if the user wants to encrypt/decrypt another message
            System.out.print("\nDo you want to input another message and key? (yes/no): ");
            String continueFurther = sc.nextLine().toLowerCase();
            continueProgram = (continueFurther.equals("yes") || continueFurther.equals("y"));
        }
        
        System.out.println("\nThank you for using the DES Encryption Tool!");
        sc.close();
    }
    
    /**
     * Converts a string to its binary representation
     * 
     * @param input The string to convert
     * @return Binary representation as a string of 0s and 1s
     */
    public static String stringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
        	// Convert each character to its 8-bit binary ASCII value
            result.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        }
        return result.toString();
    }
    
    /**
     * Converts a binary string back to a regular text string
     * 
     * @param binary The binary string to convert
     * @return The text representation
     */
    public static String binaryToString(String binary) {
        StringBuilder text = new StringBuilder();
        // Process 8 bits at a time (one ASCII character)
        for (int i = 0; i < binary.length(); i += 8) {
            String byteStr = binary.substring(i, i + 8);
            int charCode = Integer.parseInt(byteStr, 2);
            text.append((char) charCode);
        }
        return text.toString();
    }
    
    /**
     * Encrypts binary data using DES with detailed output (process)
     * 
     * @param plain The 64-bit binary plaintext string
     * @param roundKeys Array of 16 round keys
     * @return The encrypted binary ciphertext
     */
    public static String encrypt(String plain, String[] roundKeys) {
        System.out.println("Starting encryption with plaintext: " + plain);
        
        // Step 1: Apply initial permutation
        String permuted = permute(plain, IP);
        System.out.println("After initial permutation: " + permuted);
        
        // Step 2: Split into left and right halves
        String left = permuted.substring(0, 32);
        String right = permuted.substring(32);
        System.out.println("Initial L0: " + left);
        System.out.println("Initial R0: " + right);
        
        // Step 3: Perform 16 rounds of encryption
        for (int i = 0; i < 16; i++) {
            System.out.println("\nRound " + (i + 1) + ":");
            String temp = right;
            // Apply Feistel function to right half and XOR with left half
            String feistelResult = feistel(right, roundKeys[i]);
            System.out.println("  f(R" + i + ",K" + (i + 1) + "): " + feistelResult);
            
            right = xor(left, feistelResult);
            System.out.println("  R" + (i + 1) + ": " + right);
            
            left = temp;
            
            System.out.println("  L" + (i + 1) + ": " + left);
        }
        
        // Step 4: Swap left and right for the final step (R16L16 instead of L16R16)
        String combined = right + left;
        System.out.println("\nPreOutput (R16L16): " + combined);
        
        // Step 5: Apply final permutation
        String result = permute(combined, FP);
        System.out.println("After final permutation: " + result);
        
        return result;
    }

    /**
     * Encrypts binary data using DES without printing process (debug information)
     * 
     * @param plain The 64-bit binary plaintext string
     * @param roundKeys Array of 16 round keys
     * @return The encrypted binary ciphertext
     */
    public static String encryptQuiet(String plain, String[] roundKeys) {
    	// Same algorithm as encrypt() but without debug output
        String permuted = permute(plain, IP);
        
        String left = permuted.substring(0, 32);
        String right = permuted.substring(32);

        for (int i = 0; i < 16; i++) {
            String temp = right;
            String feistelResult = feistelQuiet(right, roundKeys[i]);
            
            right = xor(left, feistelResult);
            left = temp;
        }

        String combined = right + left; // Note the swap for the final step
        String result = permute(combined, FP);
        
        return result;
    }

    /**
     * Decrypts binary data using DES with detailed output for debugging
     * 
     * @param cipher The 64-bit binary ciphertext string
     * @param roundKeys Array of 16 round keys
     * @return The decrypted binary plaintext
     */
    public static String decrypt(String cipher, String[] roundKeys) {
        System.out.println("Starting decryption with ciphertext: " + cipher);
        
        // The decryption process is identical to encryption except that
        // round keys are applied in reverse order (K16 to K1)
        
        // Step 1: Apply initial permutation
        String permuted = permute(cipher, IP);
        System.out.println("After initial permutation: " + permuted);
        
        // Step 2: Split into left and right halves
        String left = permuted.substring(0, 32);
        String right = permuted.substring(32);
        System.out.println("Initial L0: " + left);
        System.out.println("Initial R0: " + right);

        // Step 3: Perform 16 rounds of encryption
        for (int i = 0; i < 16; i++) {
            System.out.println("\nRound " + (i + 1) + ":");
            String temp = right;
            // Use keys in reverse order for decryption (K16 first, then K15, etc.)
            // Apply Feistel function to right half and XOR with left half
            String feistelResult = feistel(right, roundKeys[15 - i]);  
            System.out.println("  f(R" + i + ",K" + (16 - i) + "): " + feistelResult);
            
            right = xor(left, feistelResult);
            System.out.println("  R" + (i + 1) + ": " + right);
            
            left = temp;
            System.out.println("  L" + (i + 1) + ": " + left);
        }
        
        // Step 4: Swap left and right for the final step (R16L16 instead of L16R16)
        String combined = right + left;
        System.out.println("\nPreOutput (R16L16): " + combined);
        
        // Step 5: Apply final permutation
        String result = permute(combined, FP);
        System.out.println("After final permutation: " + result);
        
        return result;
    }
    
    /**
     * Decrypts binary data using DES without printing process (debug information)
     * 
     * @param cipher The 64-bit binary ciphertext string
     * @param roundKeys Array of 16 round keys
     * @return The decrypted binary plaintext
     */
    public static String decryptQuiet(String cipher, String[] roundKeys) {
        // Same algorithm as decrypt() but without debug output
        String permuted = permute(cipher, IP);
        
        String left = permuted.substring(0, 32);
        String right = permuted.substring(32);

        for (int i = 0; i < 16; i++) {
            String temp = right;
            String feistelResult = feistelQuiet(right, roundKeys[15 - i]); 
            
            right = xor(left, feistelResult);
            left = temp;
        }

        String combined = right + left;
        String result = permute(combined, FP);
        
        return result;
    }
    
    /**
     * Applies a permutation table to rearrange bits in the input string
     * 
     * @param input The input binary string
     * @param table The permutation table (array of bit positions)
     * @return The permuted output string
     */
    public static String permute(String input, int[] table) {
        StringBuilder output = new StringBuilder();
        for (int i : table) {
            output.append(input.charAt(i - 1));
        }
        return output.toString();
    }
    
    /**
     * Performs bitwise XOR operation on two binary strings
     * 
     * @param a First binary string
     * @param b Second binary string
     * @return Result of XOR operation as a binary string
     */
    public static String xor(String a, String b) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
        	// XOR: output is 1 if inputs differ, 0 if they're the same
            result.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return result.toString();
    }

    /**
     * Implements the Feistel function used in each round of DES encryption
     * with detailed output for debugging
     * 
     * @param right The 32-bit right half of the data
     * @param key The 48-bit round key
     * @return The 32-bit result of the Feistel function
     */
    public static String feistel(String right, String key) {
        // Step 1: Expand right half from 32 to 48 bits
        String expanded = permute(right, E);
        System.out.println("    Expanded R: " + expanded);
        
        // Step 2: XOR with round key
        String xored = xor(expanded, key);
        System.out.println("    After XOR with key: " + xored);
        
        // Step 3: S-Box substitution (48 bits to 32 bits)
        StringBuilder sBoxOutput = new StringBuilder();
        for (int i = 0; i < 8; i++) {
        	// Process 6 bits at a time through the 8 S-boxes
            String block = xored.substring(i * 6, (i + 1) * 6);
            // First and last bits determine row (0-3)
            int row = Integer.parseInt(block.charAt(0) + "" + block.charAt(5), 2);
            // Middle 4 bits determine column (0-15)
            int col = Integer.parseInt(block.substring(1, 5), 2);
            
            // Get value from S-box
            int value = SBOX[i][row][col];
            // Convert to 4-bit binary
            String binary = String.format("%4s", Integer.toBinaryString(value)).replace(' ', '0');
            sBoxOutput.append(binary);
        }
        System.out.println("    After S-Box substitution: " + sBoxOutput);
        
        // Step 4: Permutation P
        String result = permute(sBoxOutput.toString(), P);
        System.out.println("    After permutation P: " + result);
        
        return result;
    }
    
    
    /**
     * Implements the Feistel function without printing debug information
     * 
     * @param right The 32-bit right half of the data
     * @param key The 48-bit round key
     * @return The 32-bit result of the Feistel function
     */
    public static String feistelQuiet(String right, String key) {
    	// Same algorithm as feistel() but without debug output
        String expanded = permute(right, E);
        String xored = xor(expanded, key);
        
 
        StringBuilder sBoxOutput = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            String block = xored.substring(i * 6, (i + 1) * 6);
            int row = Integer.parseInt(block.charAt(0) + "" + block.charAt(5), 2);
            int col = Integer.parseInt(block.substring(1, 5), 2);
            
            int value = SBOX[i][row][col];
            String binary = String.format("%4s", Integer.toBinaryString(value)).replace(' ', '0');
            sBoxOutput.append(binary);
        }
        
        String result = permute(sBoxOutput.toString(), P);
        return result;
    }
    
   /**
    * Generates all 16 round keys from the original key
    * 
    * @param key The 64-bit original key as a binary string
    * @return Array of 16 round keys (48 bits each)
    */
    public static String[] generateKeys(String key) {
    	// Step 1: Apply PC1 permutation to remove parity bits and get 56-bit key
        String permutedKey = permute(key, PC1);
        
        // Step 2: Split into left and right halves (28 bits each)
        String C = permutedKey.substring(0, 28);
        String D = permutedKey.substring(28);
        
        String[] keys = new String[16];

        // Generate 16 round keys
        for (int i = 0; i < 16; i++) {
        	// Perform left shifts according to the shift schedule
            C = leftShift(C, SHIFTS[i]);
            D = leftShift(D, SHIFTS[i]);
            
            // Combine C and D and apply PC2 to get the 48-bit round key
            String combined = C + D;
            keys[i] = permute(combined, PC2);
        }
        return keys;
    }
    
    /**
     * Performs a circular left shift on a binary string
     * 
     * @param input The input binary string
     * @param n Number of positions to shift
     * @return The shifted binary string
     */
    public static String leftShift(String input, int n) {
        return input.substring(n) + input.substring(0, n);
    }
}