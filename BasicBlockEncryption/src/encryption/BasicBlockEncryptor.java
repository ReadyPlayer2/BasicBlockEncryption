package encryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Basic encryption/decryption program developed for an assignment. 
 * 
 * @author ReadyPlayer2
 *
 */
public class BasicBlockEncryptor {
	 // Global variables
    private static String option;
    private static String password;
    private static String inputFile;
    private static String outputFile;
    private static byte [] key;
    private enum MODE { ENCRYPT, DECRYPT };
    private static MODE operation;

    // Allow command line arguments (option, key, inputFile, outputFile)
    public static void main(String[] args) throws IOException {
            
        if (args.length != 4) {
            // Throw error
            System.err.println("Error: Invalid number of arguments");
            getArgumentHelp();
            // Exit program
            return;
        }
        
        // Match arguments with variables
        option = args[0];
        password = args[1];
        inputFile = args[2];
        outputFile = args[3];
        
        // Output arguments
        System.out.println("****Command line args****");
        System.out.println("option: " + option);
        System.out.println("password: " + password);
        System.out.println("inputFile: " + inputFile);
        System.out.println("outputFile: " + outputFile);
        System.out.println("*************************\n");
        
        // Validate inputs
        validateInput(option, password, inputFile, outputFile);
        
        // Generate the key from the password
        key = generateKey(password);
        
        // Performance variables
        File inFile = new File(inputFile);
        long fileSizeKB = inFile.length()/1000;
        long time = System.currentTimeMillis();
        
        // Encrypt or Decrypt
        if (operation == MODE.ENCRYPT) {
            encrypt(key, inputFile, outputFile);
            System.out.println("Encryption complete!");
            
            // Output performance metrics
            long timeElapsed = System.currentTimeMillis() - time;
            System.out.println("Time elapsed:\t\t" + timeElapsed + "ms\n" +
                                "File size:\t\t" + fileSizeKB + "KB");
        } else {
            decrypt(key, inputFile, outputFile);
            System.out.println("Decryption complete!");
            
            // Output performance metrics
            long timeElapsed = System.currentTimeMillis() - time;
            System.out.println("Time elapsed:\t\t" + timeElapsed + "ms\n" +
                                "File size:\t\t" + fileSizeKB + "KB");
        }
    }    
    
    /**
     * Encrypt the inputFile using the key provided, and write to outputFile
     * 
     * @param key
     * @param inputFile
     * @param outputFile 
     */
    private static void encrypt(byte[] key, String inputFile, String outputFile) throws IOException {
        
        // Read all bytes from inputFile
        byte[] plainTextBytes = readFromFile(inputFile);
        // Encrypt all bytes from inputFile
        byte[] cipherTextBytes = permutateArray(key, plainTextBytes);
        
        // Write cipher text to outputFile
        writeToFile(cipherTextBytes, outputFile);
    }
    
    /**
     * Decrypt the inputFile using the key provided, and write to the outputFile
     * 
     * @param key
     * @param inputFile
     * @param outputFile 
     */
    private static void decrypt(byte[] key, String inputFile, String outputFile) throws IOException {
        
        // Read all bytes from inputFile
        byte[] cipherTextBytes = readFromFile(inputFile);
        // Decrypt all bytes from inputFile
        byte[] plainTextBytes = inversePermutateArray(key, cipherTextBytes);
        
        // Write plain text to outputFile
        writeToFile(plainTextBytes, outputFile);
    }
    
    /**
     * Use MD5 hash to generate a one-way pseudo-random 16-byte (128-bit) key 
     * from the password provided
     * 
     * @param password
     * @return byte array of key
     */
    private static byte[] generateKey(String password) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Error: " + nsae.getMessage());
            System.exit(0);
        }
        
        // MD5 hash hte password bytes
        byte[] generatedKey = md.digest(password.getBytes());
        
        return generatedKey; 
    }
    
    /**
     * Permutes bytes at intervals of 5, then xors the result with the key
     * 
     * @param key
     * @param plainTextBytes
     * @return permuted array of bytes
     */
    private static byte[] permutateArray(byte[] key, byte[] plainTextBytes) {
        // Remainders are excluded from permute to simplify the process
        byte[] plainTextBytesBlock = removeRemainders(plainTextBytes);
        byte[] cipherTextBytes = new byte[plainTextBytes.length];
        
        // Create temp arrays for permutation value storage
        byte[] temp1 = new byte[plainTextBytesBlock.length];
        byte[] temp2 = new byte[plainTextBytesBlock.length];
        byte[] temp3 = new byte[plainTextBytesBlock.length];
        byte[] temp4 = new byte[plainTextBytesBlock.length];
        byte[] temp5 = new byte[plainTextBytesBlock.length];
        
        // Get every 5th byte for starting positions n, n+1, n+2, n+3, n+4
        int i = 0;
        int turn = 1;
        while (i < plainTextBytesBlock.length) {
            switch (turn) {
                case 1:
                    temp1[i] = plainTextBytesBlock[i];
                    turn++;
                    i++;
                    break;
                case 2:
                    temp2[i] = plainTextBytesBlock[i];
                    turn++;
                    i++;
                    break;
                case 3:
                    temp3[i] = plainTextBytesBlock[i];
                    turn++;
                    i++;
                    break;
                case 4:
                    temp4[i] = plainTextBytesBlock[i];
                    turn++;
                    i++;
                    break;
                case 5:
                    temp5[i] = plainTextBytesBlock[i];
                    turn = 1;
                    i++;
                    break;
            }
        }
        
        //Concatenate bytes to a single array, if not 0
        int position = 0;
        for (byte b: temp1) {
            if (b != 0) {
                cipherTextBytes[position] = b;
                position++;
            }
        }
        for (byte b: temp2) {
            if (b != 0) {
                cipherTextBytes[position] = b;
                position++;
            }  
        }
        for (byte b: temp3) {
            if (b != 0) {
                cipherTextBytes[position] = b;
                position++;
            }
        }
        for (byte b: temp4) {
            if (b != 0) {
                cipherTextBytes[position] = b;
                position++;
            }
        }
        for (byte b: temp5) {
            if (b != 0) {
                cipherTextBytes[position] = b;
                position++;
            }
        }
        
        // Append the remainder bytes which were removed
        cipherTextBytes = appendRemainders(plainTextBytes, cipherTextBytes);
        
        // xor bytes with the key
        byte[] xorBytes = xorBytes(key, cipherTextBytes);
        
        return xorBytes;
    }
    
    /**
     * Does the opposite of permutateArray()
     * 
     * @param key
     * @param cipherTextBytes
     * @return result of xor using the key and reversing the permutation.
     */
    private static byte[] inversePermutateArray(byte[] key, byte[] cipherTextBytes) {
        // xor the bytes with the key
        byte[] undoXorBytes = xorBytes(key, cipherTextBytes);
        
        // Remainders are excluded from permute to simplify the process
        byte[] cipherTextBytesBlock = removeRemainders(undoXorBytes);
        byte[] plainTextBytes = new byte[undoXorBytes.length];
        
        // plaintext length / blocksize
        int offset = cipherTextBytesBlock.length / 5;
        byte[] temp1 = new byte[offset];
        byte[] temp2 = new byte[offset];
        byte[] temp3 = new byte[offset];
        byte[] temp4 = new byte[offset];
        byte[] temp5 = new byte[offset];
        
        // Split the bytes into 5 equal size arrays
        int pos = 0;
        while (pos < offset) {
            temp1[pos] = undoXorBytes[pos];
            temp2[pos] = undoXorBytes[pos+(offset*1)];
            temp3[pos] = undoXorBytes[pos+(offset*2)];
            temp4[pos] = undoXorBytes[pos+(offset*3)];
            temp5[pos] = undoXorBytes[pos+(offset*4)];
            pos++;
        }
        
        // Get the first byte from each array and append to plaintext. Repeat for all bytes
        int plainTextPos = 0;
        int tempArrayPos = 0;
        int turn = 1;
        while (tempArrayPos < offset) {
            switch (turn) {
                case 1:
                    plainTextBytes[plainTextPos] = temp1[tempArrayPos];
                    turn++;
                    plainTextPos++;
                    break;
                case 2:
                    plainTextBytes[plainTextPos] = temp2[tempArrayPos];
                    turn++;
                    plainTextPos++;
                    break;
                case 3:
                    plainTextBytes[plainTextPos] = temp3[tempArrayPos];
                    turn++;
                    plainTextPos++;
                    break;
                case 4:
                    plainTextBytes[plainTextPos] = temp4[tempArrayPos];
                    turn++;
                    plainTextPos++;
                    break;
                case 5:
                    plainTextBytes[plainTextPos] = temp5[tempArrayPos];
                    turn = 1;
                    plainTextPos++;
                    tempArrayPos++;
                    break;
            }
        }
        
        //Append excess bytes which were removed
        plainTextBytes = appendRemainders(undoXorBytes, plainTextBytes);
        
        return plainTextBytes;
    }
    
    /**
     * Writes text to file (creates the file if it doesn't already exist)
     * 
     * @param text
     * @param outputFile
     * @throws IOException 
     */
    private static void writeToFile(byte[] bytes, String outputFile) throws IOException {
        try (FileOutputStream fOutStream = new FileOutputStream(outputFile)) {
            // Write all bytes to the outputFile
            fOutStream.write(bytes);
            fOutStream.close();
        } catch (IOException ioe) {
            throw new IOException("Error: " + ioe.getMessage());
        }
    }
    
    /**
     * Reads all text bytes from file and returns as a byte array
     * 
     * @param inputFile
     * @return String
     * @throws IOException 
     */
    private static byte[] readFromFile(String inputFile) throws IOException{
        // Read all bytes in the inputFile
        return Files.readAllBytes(Paths.get(inputFile));
    }
    
    /**
     * Does an xor operation on each byte in beforeBytes, looping through the 
     * bytes in the key for the second byte value.
     * 
     * Example Key: THEKEY
     * 1st xor: byte1 ^ T
     * 2nd xor: byte2 ^ H
     * (...)
     * 6th xor: byte6 ^ Y
     * 7th xor: byte7 ^ T
     * 
     * @param key
     * @param beforeXorBytes
     * @return array of bytes after xor operation
     */
    private static byte[] xorBytes(byte[] key, byte[] beforeXorBytes) {
        byte[] afterXorBytes = new byte[beforeXorBytes.length];
        
        /**
         * For each byte, xor with a byte from key. Key bytes are looped through
         * using remainders.
         */
        for (int i = 0;i < beforeXorBytes.length; i++) {
            afterXorBytes[i] = (byte) (beforeXorBytes[i] ^ key[i % key.length]);
        }
        
        return afterXorBytes;
    }
    
    /**
     * Calculates if there is a remainder when divided by 5, and removes the extra
     * bytes as this would cause problems with the permutation. If there is no
     * remainder, the same array is returned.
     * 
     * @param beforeBytes
     * @return a byte array
     */
    private static byte[] removeRemainders(byte[] beforeBytes) {        
        int length = beforeBytes.length;
        int remainder = length % 5;
        
        if (remainder != 0) {
            byte[] afterBytes = Arrays.copyOfRange(beforeBytes, 0, length - remainder);
            
            // Return the array without the extra chars
            return afterBytes;
        } else {
            // Return the array uneditted
            return beforeBytes;
        }
    }
    
    /**
     * Appends the missing end chars from beforeBytes to the afterBytes and returns
     * the result. If there is no remainder bytes, the same array is returned
     * @param beforeBytes
     * @param afterBytes
     * @return 
     */
    private static byte[] appendRemainders(byte[] beforeBytes, byte[] afterBytes) {
        int length = beforeBytes.length;
        int remainder = length % 5;
        
        if (remainder == 0) {
            // Return the array uneditted
            return afterBytes;
        } else {
            while (remainder > 0) {
                afterBytes[length - remainder] = beforeBytes[length - remainder];
                remainder--;
            }
            // Return the array with the extra chars appended to it
            return afterBytes;
        }
    }
    
    
    /**
     * Validates input
     * 
     * @param option
     * @param password
     * @param inputFile
     * @param outputFile 
     */
    private static void validateInput(String option, String password, String inputFile, String outputFile) {
               
        if (option.equalsIgnoreCase("-e")) {
        	operation = MODE.ENCRYPT;
        } else if (option.equalsIgnoreCase("-d")) {
        	operation = MODE.DECRYPT;
        } else {
            // Throw error
            System.err.println("Error: Invalid option");
            getArgumentHelp();
            // Exit program
            System.exit(0);
        }
        
        // Validate length of key argument (10-40)
        if (password.length() < 10 || password.length() > 40) {
            // Throw error
            System.err.println("Error: Invalid password length (must be 10-40 chars)");
            // Exit program
            System.exit(0);
        }
        
        if (!inputFile.contains(".txt") || !outputFile.contains(".txt")) {
            // Throw error
            System.err.println("Error: Invalid input/output file (must be a .txt file)");
            // Exit program
            System.exit(0);
        }
        
    }
    
    /**
     * Displays help on how to run the program
     */
    public static void getArgumentHelp() {
        System.out.println("\nCommand line help:\n"
                + "Encryption:\n"
                + "java -jar \"<JarFileDirectory>\" -e password \"<InputFile>\" \"<OutputFile>\"\n\n"
                + "Decryption:\n"
                + "java -jar \"<JarFileDirectory>\" -d password \"<InputFile>\" \"<OutputFile>\"\n");
    }
    
}
